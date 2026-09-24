//go:build e2e && linux

package tordriver_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
)

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
	for _, evidence := range []string{"ipv4_denied=true", "ipv6_denied=true", "dns_denied=true"} {
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
