//go:build linux

package direct

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

func TestContainmentRulesCoverIPv4IPv6AndDescendants(t *testing.T) {
	rules := containmentRules("tor_driver_test", "one/two/three/child", 4)
	for _, want := range []string{
		"socket cgroupv2 level 4 \"one/two/three/child\"",
		"ip daddr != 127.0.0.0/8",
		"ip6 daddr != ::1",
		"counter name blocked_ipv4",
		"counter name blocked_ipv6",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("rules do not contain %q:\n%s", want, rules)
		}
	}
}

func TestProcessAdapterWaitKillAndRelease(t *testing.T) {
	executable, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep executable not available")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		t.Fatal(err)
	}
	system := System{}
	if os.Geteuid() == 0 {
		t.Skip("test does not select a host-specific non-root identity")
	}
	p, err := system.Start(context.Background(), tor.Launch{Executable: executable, Args: []string{"30"}, Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = p.Wait(); err == nil {
		t.Fatal("killed process returned no wait error")
	}
	if err = p.Release(); err != nil {
		t.Fatal(err)
	}
	if err = p.Release(); err != nil {
		t.Fatal(err)
	}
}
