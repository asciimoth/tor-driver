//go:build windows

package direct

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
	"golang.org/x/sys/windows"
)

// WindowsContainmentConfig configures a restricted-token and Windows Firewall
// process boundary. Executables must contain every approved Tor and PT binary.
// Creating firewall rules requires an elevated process.
type WindowsContainmentConfig struct {
	Executables          []string
	PowerShellExecutable string
}

// ContainedSystem is a single-use Windows Process adapter. It blocks external
// IPv4 and IPv6 traffic for the approved executable paths. Windows Firewall
// does not filter loopback traffic, which remains available to Tor and its PTs.
type ContainedSystem struct {
	System
	mu          sync.Mutex
	powershell  string
	group       string
	executables map[string]struct{}
	started     bool
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

// NewContainedSystem installs the firewall boundary before Tor can start. It
// returns an error if enforcement is unavailable and never falls back.
func NewContainedSystem(cfg WindowsContainmentConfig) (*ContainedSystem, error) {
	approved := make(map[string]struct{}, len(cfg.Executables))
	for _, path := range cfg.Executables {
		clean := filepath.Clean(path)
		if !filepath.IsAbs(clean) {
			return nil, fmt.Errorf("direct: contained executable path must be absolute")
		}
		approved[strings.ToLower(clean)] = struct{}{}
	}
	if len(approved) == 0 {
		return nil, fmt.Errorf("direct: contained executables are required")
	}
	powershell := cfg.PowerShellExecutable
	if powershell == "" {
		var err error
		powershell, err = exec.LookPath("powershell.exe")
		if err != nil {
			return nil, fmt.Errorf("direct: PowerShell unavailable: %w", err)
		}
	}
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	s := &ContainedSystem{powershell: powershell, group: "tor-driver-" + hex.EncodeToString(token[:]), executables: approved}
	for path := range approved {
		if err := s.addFirewallRule(path); err != nil {
			cleanupErr := s.Close()
			return nil, errors.Join(fmt.Errorf("direct: install Windows containment firewall: %w", err), cleanupErr)
		}
	}
	return s, nil
}

func (s *ContainedSystem) runPowerShell(script string, args ...string) error {
	commandArgs := append([]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script}, args...)
	output, err := exec.Command(s.powershell, commandArgs...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 1024 {
			message = message[:1024]
		}
		return errors.Join(err, fmt.Errorf("PowerShell: %s", message))
	}
	return nil
}

func (s *ContainedSystem) addFirewallRule(path string) error {
	const script = `& { param($group,$program) New-NetFirewallRule -Group $group -DisplayName $group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $program -RemoteAddress '0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' | Out-Null }`
	return s.runPowerShell(script, s.group, path)
}

// Dependencies returns dependencies that use this contained Process adapter.
func (s *ContainedSystem) Dependencies(local, outbound gonnect.Network, logger tor.Logger) tor.Dependencies {
	deps := Dependencies(local, outbound, logger)
	deps.Processes = s
	return deps
}

func restrictedToken() (windows.Token, error) {
	var current windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &current); err != nil {
		return 0, err
	}
	defer func() { _ = current.Close() }()
	var restricted windows.Token
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	const disableMaxPrivilege = 0x1
	result, _, callErr := proc.Call(uintptr(current), disableMaxPrivilege, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if result == 0 {
		return 0, callErr
	}
	return restricted, nil
}

// Start launches one approved executable with unnecessary token privileges
// disabled. The executable is assigned to the normal kill-on-close Job.
func (s *ContainedSystem) Start(ctx context.Context, spec tor.Launch) (tor.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		return nil, fmt.Errorf("direct: contained system is single-use")
	}
	_, approved := s.executables[strings.ToLower(filepath.Clean(spec.Executable))]
	s.started = true
	s.mu.Unlock()
	if !approved {
		_ = s.Close()
		return nil, fmt.Errorf("direct: executable is not approved for containment")
	}
	token, err := restrictedToken()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	cmd := launchCommand(spec)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	p, err := startProcess(cmd, spec.Identity)
	_ = token.Close()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return &containedProcess{Process: p, owner: s}, nil
}

// Close removes the temporary firewall rules.
func (s *ContainedSystem) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		const script = `& { param($group) Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule }`
		s.closeErr = s.runPowerShell(script, s.group)
	})
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
