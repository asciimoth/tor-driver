//go:build linux

package direct

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

// LinuxContainmentConfig configures an optional cgroup v2 and nftables
// boundary. The caller must be able to create a child cgroup, but the Tor
// identity must not be able to move itself to the parent cgroup. An empty
// NFTablesExecutable searches PATH for nft. Installing rules requires the
// network-administration capability in the containing network namespace.
type LinuxContainmentConfig struct {
	CgroupParent       string
	NFTablesExecutable string
}

// ContainmentStats contains packets that Tor or one of its descendants tried
// to send to a non-loopback IPv4 or IPv6 destination.
type ContainmentStats struct {
	BlockedIPv4 uint64
	BlockedIPv6 uint64
}

// ContainedSystem is a single-use Linux Process adapter. Its nftables rules
// allow Tor and inherited PT children to use loopback TCP/UDP endpoints only.
// The application-owned upstream proxy is outside the child cgroup and keeps
// using its injected outbound Network. Call Close if Start is never called.
type ContainedSystem struct {
	System
	mu        sync.Mutex
	parent    string
	cgroup    *processCgroup
	nft       string
	table     string
	started   bool
	closed    bool
	closeOnce sync.Once
	done      chan struct{}
	closeErr  error
}

// NewContainedSystem installs a fail-closed Linux process boundary before Tor
// can start. It returns an error if cgroup v2 or nftables enforcement is not
// available; it never silently falls back to the ordinary System adapter.
func NewContainedSystem(cfg LinuxContainmentConfig) (*ContainedSystem, error) {
	parent, err := resolveCgroupParent(cfg.CgroupParent)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		writable, writeErr := cgroupParentWritableByCaller(parent, os.Geteuid(), os.Getegid())
		if writeErr != nil {
			return nil, fmt.Errorf("direct: inspect delegated cgroup parent: %w", writeErr)
		}
		if writable {
			return nil, fmt.Errorf("direct: strict containment requires a cgroup parent the child identity cannot modify")
		}
	}
	group, err := newProcessCgroup(parent, true)
	if err != nil {
		return nil, err
	}
	nft := cfg.NFTablesExecutable
	if nft == "" {
		nft, err = exec.LookPath("nft")
	} else if !filepath.IsAbs(nft) {
		err = fmt.Errorf("direct: nftables executable must be absolute")
	}
	if err != nil {
		_ = group.close()
		return nil, errors.Join(fmt.Errorf("direct: nftables executable unavailable"), err)
	}
	var token [8]byte
	if _, err = rand.Read(token[:]); err != nil {
		_ = group.close()
		return nil, err
	}
	s := &ContainedSystem{parent: parent, cgroup: group, nft: nft, table: "tor_driver_" + hex.EncodeToString(token[:]), done: make(chan struct{})}
	if err = s.installFirewall(); err != nil {
		_ = group.close()
		return nil, err
	}
	return s, nil
}

// Dependencies returns dependencies that use this contained Process adapter.
// Local and outbound Networks remain caller-selected and caller-owned.
func (s *ContainedSystem) Dependencies(local, outbound gonnect.Network, logger tor.Logger) tor.Dependencies {
	deps := Dependencies(local, outbound, logger)
	deps.Processes = s
	return deps
}

func (s *ContainedSystem) installFirewall() error {
	name, level := s.cgroup.pathAndLevel()
	rules := containmentRules(s.table, name, level)
	if _, err := s.runNFT(context.Background(), rules, "-f", "-"); err != nil {
		return fmt.Errorf("direct: install containment firewall: %w", err)
	}
	return nil
}

func containmentRules(table, cgroup string, level int) string {
	return fmt.Sprintf(`add table inet %s
add counter inet %s blocked_ipv4
add counter inet %s blocked_ipv6
add chain inet %s output { type filter hook output priority -300; policy accept; }
add rule inet %s output socket cgroupv2 level %d %q ip daddr != 127.0.0.0/8 counter name blocked_ipv4 reject with icmpx type admin-prohibited
add rule inet %s output socket cgroupv2 level %d %q ip6 daddr != ::1 counter name blocked_ipv6 reject with icmpx type admin-prohibited
`, table, table, table, table, table, level, cgroup, table, level, cgroup)
}

func (s *ContainedSystem) runNFT(ctx context.Context, input string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.nft, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(output.String())
		if len(message) > 1024 {
			message = message[:1024]
		}
		if message != "" {
			err = errors.Join(err, fmt.Errorf("nft: %s", message))
		}
		return nil, err
	}
	return output.Bytes(), nil
}

// Start launches exactly one process in the pre-filtered cgroup. The kernel
// places the process in the cgroup during clone, before it can create a socket.
// The process does not inherit ambient capabilities from the caller.
func (s *ContainedSystem) Start(ctx context.Context, spec tor.Launch) (tor.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		return nil, fmt.Errorf("direct: contained system is single-use")
	}
	s.started = true
	s.mu.Unlock()
	if os.Geteuid() == 0 && spec.Identity != nil {
		writable, writeErr := cgroupParentWritableByIdentity(s.parent, spec.Identity)
		if writeErr != nil {
			_ = s.Close()
			return nil, fmt.Errorf("direct: inspect cgroup parent for child identity: %w", writeErr)
		}
		if writable {
			_ = s.Close()
			return nil, fmt.Errorf("direct: strict containment requires a cgroup parent the child identity cannot modify")
		}
	}
	p, err := startProcessInCgroup(launchCommand(spec), spec.Identity, s.cgroup)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return &containedProcess{Process: p, owner: s}, nil
}

var packetsPattern = regexp.MustCompile(`packets ([0-9]+) bytes`)

// Stats reads the kernel packet counters while the containment table exists.
func (s *ContainedSystem) Stats(ctx context.Context) (ContainmentStats, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ContainmentStats{}, fmt.Errorf("direct: contained system is closed")
	}
	table := s.table
	s.mu.Unlock()
	read := func(name string) (uint64, error) {
		output, err := s.runNFT(ctx, "", "list", "counter", "inet", table, name)
		if err != nil {
			return 0, err
		}
		match := packetsPattern.FindSubmatch(output)
		if len(match) != 2 {
			return 0, fmt.Errorf("direct: nftables counter output was not understood")
		}
		return strconv.ParseUint(string(match[1]), 10, 64)
	}
	v4, err := read("blocked_ipv4")
	if err != nil {
		return ContainmentStats{}, err
	}
	v6, err := read("blocked_ipv6")
	return ContainmentStats{BlockedIPv4: v4, BlockedIPv6: v6}, err
}

// Close kills remaining processes in the cgroup and removes the firewall and
// cgroup. Normally Driver.Close calls Process.Release, which does this work.
func (s *ContainedSystem) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		groupErr := s.cgroup.close()
		empty, emptyErr := s.cgroup.empty()
		var nftErr error
		if empty && emptyErr == nil {
			_, nftErr = s.runNFT(context.Background(), "", "delete", "table", "inet", s.table)
		} else {
			nftErr = fmt.Errorf("direct: containment firewall retained because the cgroup is not confirmed empty")
		}
		s.mu.Lock()
		s.closeErr = errors.Join(groupErr, emptyErr, nftErr)
		s.mu.Unlock()
		close(s.done)
	})
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

type containedProcess struct {
	tor.Process
	owner *ContainedSystem
	once  sync.Once
	err   error
}

func (p *containedProcess) Release() error {
	p.once.Do(func() { p.err = errors.Join(p.Process.Release(), p.owner.Close()) })
	return p.err
}

var _ tor.Processes = (*ContainedSystem)(nil)
