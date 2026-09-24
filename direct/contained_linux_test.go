//go:build linux

package direct

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

func TestCgroupEventsEmptyRequiresExactUnpopulatedState(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want bool
	}{
		{name: "empty", data: "populated 0\nfrozen 0\n", want: true},
		{name: "populated", data: "populated 1\nfrozen 0\n"},
		{name: "prefix", data: "populated 00\n"},
		{name: "missing", data: "frozen 0\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := cgroupEventsEmpty([]byte(test.data)); got != test.want {
				t.Fatalf("cgroupEventsEmpty() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCgroupParentWritableChecksMigrationFile(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "cgroup.procs")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	writable, err := cgroupParentWritable(parent)
	if err != nil || !writable {
		t.Fatalf("writable parent = (%v, %v), want (true, nil)", writable, err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = cgroupParentWritable(parent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing migration file error = %v", err)
	}
}

func TestProcessCgroupEmptyUsesKernelState(t *testing.T) {
	path := t.TempDir()
	cgroup := &processCgroup{path: path}
	events := filepath.Join(path, "cgroup.events")
	for _, test := range []struct {
		name string
		data string
		want bool
	}{
		{name: "populated", data: "populated 1\n"},
		{name: "empty", data: "populated 0\n", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(events, []byte(test.data), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := cgroup.empty()
			if err != nil || got != test.want {
				t.Fatalf("empty() = (%v, %v), want (%v, nil)", got, err, test.want)
			}
		})
	}
	if err := os.Remove(events); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if empty, err := cgroup.empty(); err != nil || !empty {
		t.Fatalf("empty() after removal = (%v, %v), want (true, nil)", empty, err)
	}
}

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
