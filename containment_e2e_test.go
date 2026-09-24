//go:build e2e && linux

package tordriver_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
	"golang.org/x/sys/unix"
)

var capabilityChild = flag.Bool("tor-driver-capability-child", false, "run the ambient-capability child probe")

func processCapability(t *testing.T, name string) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name+":" {
			value, parseErr := strconv.ParseUint(fields[1], 16, 64)
			if parseErr != nil {
				t.Fatalf("parse %s value %q: %v", name, fields[1], parseErr)
			}
			return value
		}
	}
	t.Fatalf("%s was not found in /proc/self/status", name)
	return 0
}

func copyTestExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helperDir, err := os.MkdirTemp("/tmp", "tor-driver-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(helperDir) })
	if err = os.Chmod(helperDir, 0755); err != nil {
		t.Fatal(err)
	}
	helperExecutable := filepath.Join(helperDir, "tor-driver.test")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.OpenFile(helperExecutable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if _, err = io.Copy(destination, source); err != nil {
		_ = source.Close()
		_ = destination.Close()
		t.Fatal(err)
	}
	if err = errors.Join(source.Close(), destination.Close()); err != nil {
		t.Fatal(err)
	}
	return helperExecutable
}

func TestTorLinuxLaunchClearsAmbientCapabilities(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TOR_PT_FIXTURE_ESCAPE") == "" {
		t.Skip("run the privileged containment profile with ./e2e/run.sh")
	}
	helperExecutable := copyTestExecutable(t)
	cmd := exec.Command(helperExecutable, "-test.run=^TestTorAmbientCapabilityParentHelper$")
	cmd.Env = append(os.Environ(), "TOR_DRIVER_AMBIENT_CAPABILITY_PARENT=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{}},
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ambient-capability parent failed: %v: %s", err, output)
	}
}

func TestTorAmbientCapabilityParentHelper(t *testing.T) {
	if os.Getenv("TOR_DRIVER_AMBIENT_CAPABILITY_PARENT") != "1" {
		t.Skip("started only by TestTorLinuxLaunchClearsAmbientCapabilities")
	}
	if os.Geteuid() != 1000 {
		t.Fatalf("helper effective UID = %d, want 1000", os.Geteuid())
	}
	mask := uint64(1) << unix.CAP_NET_ADMIN
	if ambient := processCapability(t, "CapAmb"); ambient&mask == 0 {
		t.Fatalf("parent ambient capabilities = %#x, want CAP_NET_ADMIN", ambient)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	process, err := (direct.System{}).Start(context.Background(), tor.Launch{
		Executable: executable,
		Args:       []string{"-test.run=^TestTorAmbientCapabilityChildHelper$", "-tor-driver-capability-child=true"},
		Stdout:     &output,
		Stderr:     &output,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = process.Wait(); err != nil {
		_ = process.Release()
		t.Fatalf("capability child failed: %v: %s", err, output.String())
	}
	if err = process.Release(); err != nil {
		t.Fatal(err)
	}
	if ambient := processCapability(t, "CapAmb"); ambient&mask == 0 {
		t.Fatalf("parent ambient capabilities were not restored: %#x", ambient)
	}
}

func TestTorAmbientCapabilityChildHelper(t *testing.T) {
	if !*capabilityChild {
		t.Skip("started only by TestTorAmbientCapabilityParentHelper")
	}
	if ambient := processCapability(t, "CapAmb"); ambient != 0 {
		t.Fatalf("child ambient capabilities = %#x, want zero", ambient)
	}
	if effective := processCapability(t, "CapEff"); effective != 0 {
		t.Fatalf("child effective capabilities = %#x, want zero", effective)
	}
}

func TestTorContainedTransportSocketDenial(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TOR_PT_FIXTURE_ESCAPE") == "" {
		t.Skip("run the privileged containment profile with ./e2e/run.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/eth0/disable_ipv6", []byte("0"), 0600); err != nil {
		t.Fatalf("enable controlled IPv6 interface: %v", err)
	}
	if output, err := exec.Command("ip", "-6", "address", "replace", "2001:db8::2/64", "dev", "eth0").CombinedOutput(); err != nil {
		t.Fatalf("configure controlled IPv6 route: %v: %s", err, output)
	}
	contained, err := direct.NewContainedSystem(direct.LinuxContainmentConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := contained.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	state, err := os.MkdirTemp("/tmp", "tor-driver-contained-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	cfg := torConfig(t)
	cfg.Identity = &tor.Identity{UID: 1000, GID: 1000}
	cfg.StateDirectory = state
	cfg.ForwardTorLogs = true
	cfg.UseBridges = true
	cfg.Transports = []tor.TransportConfig{{Kind: tor.Obfs4, Executable: os.Getenv("TOR_PT_FIXTURE_ESCAPE")}}
	cfg.Bridges = []tor.Bridge{{
		Transport:        tor.Obfs4,
		Address:          "192.0.2.2:443",
		Fingerprint:      tor.Fingerprint(strings.Repeat("A", 40)),
		Obfs4Certificate: base64.RawStdEncoding.EncodeToString(make([]byte, 52)),
	}}
	deps := contained.Dependencies(direct.Network(), nil, testLogger{t: t})
	d, err := tor.Start(ctx, cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	report := waitTransportReport(t, state, filepath.Base(os.Getenv("TOR_PT_FIXTURE_ESCAPE")))
	for _, evidence := range []string{
		"ambient_capabilities=false",
		"effective_capabilities=false",
		"ambient_capabilities_unknown=false",
		"effective_capabilities_unknown=false",
		"cgroup_escape_attempted=true",
		"cgroup_escape_denied=true",
		"ipv4_denied=true",
		"ipv6_denied=true",
		"dns_denied=true",
	} {
		if !strings.Contains(report, evidence) {
			t.Fatalf("contained transport report lacks %q: %q", evidence, report)
		}
	}
	stats, err := contained.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.BlockedIPv4 < 2 || stats.BlockedIPv6 < 1 {
		t.Fatalf("containment counters = %+v, want IPv4/DNS and IPv6 denials", stats)
	}
}

func TestTorContainedRejectsEscapableDelegation(t *testing.T) {
	if helper := os.Getenv("TOR_DRIVER_ESCAPABLE_CGROUP_HELPER"); helper != "" {
		if os.Getenv("TOR_DRIVER_RESTORABLE_CGROUP_WRITE") == "1" {
			migration := filepath.Join(helper, "cgroup.procs")
			if err := os.Chmod(migration, 0600); err != nil {
				t.Fatalf("restore owner write permission: %v", err)
			}
			file, err := os.OpenFile(migration, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open owner-restored migration file: %v", err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(migration, 0400); err != nil {
				t.Fatalf("hide current write permission: %v", err)
			}
		}
		_, err := direct.NewContainedSystem(direct.LinuxContainmentConfig{CgroupParent: helper})
		if err == nil || !strings.Contains(err.Error(), "child identity cannot modify") {
			t.Fatalf("NewContainedSystem() error = %v", err)
		}
		return
	}
	if os.Geteuid() != 0 || os.Getenv("TOR_PT_FIXTURE_ESCAPE") == "" {
		t.Skip("run the privileged containment profile with ./e2e/run.sh")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var parent string
	for _, line := range strings.Split(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			parent = filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+path))
			break
		}
	}
	if parent == "" {
		t.Fatal("cgroup v2 parent was not found")
	}
	delegated, err := os.MkdirTemp(parent, "tor-driver-escapable-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(delegated) })
	for _, path := range []string{delegated, filepath.Join(delegated, "cgroup.procs")} {
		if err = os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	helperExecutable := copyTestExecutable(t)
	for _, test := range []struct {
		name       string
		mode       os.FileMode
		restorable bool
	}{
		{name: "currently writable", mode: 0600},
		{name: "owner can restore write", mode: 0400, restorable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			migration := filepath.Join(delegated, "cgroup.procs")
			if chmodErr := os.Chmod(migration, test.mode); chmodErr != nil {
				t.Fatal(chmodErr)
			}
			cmd := exec.Command(helperExecutable, "-test.run=^TestTorContainedRejectsEscapableDelegation$")
			cmd.Env = append(os.Environ(),
				"TOR_DRIVER_ESCAPABLE_CGROUP_HELPER="+delegated,
				fmt.Sprintf("TOR_DRIVER_RESTORABLE_CGROUP_WRITE=%d", bitForTest(test.restorable)),
			)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{}}}
			output, runErr := cmd.CombinedOutput()
			if runErr != nil {
				t.Fatalf("unprivileged containment helper failed: %v: %s", runErr, output)
			}
		})
	}
	if err = os.Chown(delegated, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func bitForTest(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestTorContainedRejectsRootDelegationWritableByChild(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TOR_PT_FIXTURE_ESCAPE") == "" {
		t.Skip("run the privileged containment profile with ./e2e/run.sh")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var parent string
	for _, line := range strings.Split(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			parent = filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+path))
			break
		}
	}
	if parent == "" {
		t.Fatal("cgroup v2 parent was not found")
	}
	delegated, err := os.MkdirTemp(parent, "tor-driver-root-delegation-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chown(delegated, 0, 0)
		_ = os.Remove(delegated)
	})
	for _, path := range []string{delegated, filepath.Join(delegated, "cgroup.procs")} {
		if err = os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	// Ownership is unsafe even without a current write bit because the owner can
	// change the mode before it tries to migrate.
	if err = os.Chmod(filepath.Join(delegated, "cgroup.procs"), 0400); err != nil {
		t.Fatal(err)
	}
	contained, err := direct.NewContainedSystem(direct.LinuxContainmentConfig{CgroupParent: delegated})
	if err != nil {
		t.Fatal(err)
	}
	process, startErr := contained.Start(context.Background(), tor.Launch{
		Executable: "/bin/true",
		Identity:   &tor.Identity{UID: 1000, GID: 1000},
	})
	if process != nil {
		_ = process.Kill()
		_ = process.Wait()
		_ = process.Release()
	}
	if startErr == nil || !strings.Contains(startErr.Error(), "child identity cannot modify") {
		t.Fatalf("Start() error = %v", startErr)
	}
	if err = contained.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTorBestEffortEnvironment(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TOR_PT_FIXTURE_ESCAPE") == "" {
		t.Skip("run the privileged containment profile with ./e2e/run.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/eth0/disable_ipv6", []byte("0"), 0600); err != nil {
		t.Fatalf("enable controlled IPv6 interface: %v", err)
	}
	if output, err := exec.Command("ip", "-6", "address", "replace", "2001:db8::2/64", "dev", "eth0").CombinedOutput(); err != nil {
		t.Fatalf("configure controlled IPv6 route: %v: %s", err, output)
	}

	bin, err := os.MkdirTemp("/tmp", "tor-driver-best-effort-bin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(bin) })
	if err := os.Chmod(bin, 0755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"tor":      os.Getenv("TOR_BINARY"),
		"lyrebird": os.Getenv("TOR_PT_FIXTURE_ESCAPE"),
	} {
		if target == "" {
			t.Fatalf("missing target for %s", name)
		}
		if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	state, err := os.MkdirTemp("/tmp", "tor-driver-best-effort-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	cfg := tor.Config{
		StateDirectory: state,
		ForwardTorLogs: true,
		UseBridges:     true,
		Transports:     []tor.TransportConfig{{Kind: tor.Obfs4}},
		Bridges: []tor.Bridge{{
			Transport:        tor.Obfs4,
			Address:          "192.0.2.2:443",
			Fingerprint:      tor.Fingerprint(strings.Repeat("A", 40)),
			Obfs4Certificate: base64.RawStdEncoding.EncodeToString(make([]byte, 52)),
		}},
	}
	system, cfg, err := direct.NewBestEffortSystem(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := system.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	report := system.Report()
	if !report.AutomaticIdentity || !report.PrivilegeDrop || report.Identity == nil || report.Identity.UID == 0 || report.Identity.GID == 0 {
		t.Fatalf("automatic identity report = %+v", report)
	}
	if !report.Containment || report.ContainmentError != nil {
		t.Fatalf("automatic containment report = %+v", report)
	}
	if got, want := cfg.TorExecutable, filepath.Join(bin, "tor"); got != want {
		t.Fatalf("Tor executable = %q, want %q", got, want)
	}
	if got, want := cfg.Transports[0].Executable, filepath.Join(bin, "lyrebird"); got != want {
		t.Fatalf("transport executable = %q, want %q", got, want)
	}

	d, err := tor.Start(ctx, cfg, system.Dependencies(direct.Network(), nil, testLogger{t: t}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	transportReport := waitTransportReport(t, state, "lyrebird")
	for _, evidence := range []string{
		"ambient_capabilities=false",
		"effective_capabilities=false",
		"ambient_capabilities_unknown=false",
		"effective_capabilities_unknown=false",
		"ipv4_denied=true",
		"ipv6_denied=true",
		"dns_denied=true",
		fmt.Sprintf("uid=%d", report.Identity.UID),
		fmt.Sprintf("gid=%d", report.Identity.GID),
	} {
		if !strings.Contains(transportReport, evidence) {
			t.Fatalf("automatic transport report lacks %q: %q", evidence, transportReport)
		}
	}
	stats, err := system.ContainmentStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.BlockedIPv4 < 2 || stats.BlockedIPv6 < 1 {
		t.Fatalf("automatic containment counters = %+v, want IPv4/DNS and IPv6 denials", stats)
	}
}
