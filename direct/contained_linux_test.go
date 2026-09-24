//go:build linux

package direct

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

type fakeAmbientCapabilityControl struct {
	capabilities []uintptr
	currentErr   error
	clearErr     error
	raiseErrors  map[uintptr]error
	calls        []string
}

func (f *fakeAmbientCapabilityControl) current() ([]uintptr, error) {
	f.calls = append(f.calls, "current")
	return append([]uintptr(nil), f.capabilities...), f.currentErr
}

func (f *fakeAmbientCapabilityControl) clear() error {
	f.calls = append(f.calls, "clear")
	return f.clearErr
}

func (f *fakeAmbientCapabilityControl) raise(capability uintptr) error {
	f.calls = append(f.calls, fmt.Sprintf("raise:%d", capability))
	return f.raiseErrors[capability]
}

func TestRunWithoutAmbientCapabilities(t *testing.T) {
	currentErr := errors.New("inspect failed")
	clearErr := errors.New("clear failed")
	actionErr := errors.New("action failed")
	restoreFirstErr := errors.New("restore first failed")
	restoreSecondErr := errors.New("restore second failed")
	for _, test := range []struct {
		name            string
		control         *fakeAmbientCapabilityControl
		actionErr       error
		wantRan         bool
		wantAction      bool
		wantActionErr   error
		wantControlErrs []error
		wantCalls       []string
	}{
		{
			name:       "no capabilities",
			control:    &fakeAmbientCapabilityControl{},
			wantRan:    true,
			wantAction: true,
			wantCalls:  []string{"current", "action"},
		},
		{
			name:            "inspection failure",
			control:         &fakeAmbientCapabilityControl{currentErr: currentErr},
			wantControlErrs: []error{currentErr},
			wantCalls:       []string{"current"},
		},
		{
			name:            "clear failure",
			control:         &fakeAmbientCapabilityControl{capabilities: []uintptr{12}, clearErr: clearErr},
			wantControlErrs: []error{clearErr},
			wantCalls:       []string{"current", "clear"},
		},
		{
			name:       "capabilities cleared and restored",
			control:    &fakeAmbientCapabilityControl{capabilities: []uintptr{12, 21}},
			wantRan:    true,
			wantAction: true,
			wantCalls:  []string{"current", "clear", "action", "raise:12", "raise:21"},
		},
		{
			name:          "action failure still restores",
			control:       &fakeAmbientCapabilityControl{capabilities: []uintptr{12, 21}},
			actionErr:     actionErr,
			wantRan:       true,
			wantAction:    true,
			wantActionErr: actionErr,
			wantCalls:     []string{"current", "clear", "action", "raise:12", "raise:21"},
		},
		{
			name: "all restore failures are reported",
			control: &fakeAmbientCapabilityControl{
				capabilities: []uintptr{12, 21},
				raiseErrors:  map[uintptr]error{12: restoreFirstErr, 21: restoreSecondErr},
			},
			wantRan:         true,
			wantAction:      true,
			wantControlErrs: []error{restoreFirstErr, restoreSecondErr},
			wantCalls:       []string{"current", "clear", "action", "raise:12", "raise:21"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			actionCalled := false
			ran, gotActionErr, gotControlErr := runWithoutAmbientCapabilities(test.control, func() error {
				actionCalled = true
				test.control.calls = append(test.control.calls, "action")
				return test.actionErr
			})
			if ran != test.wantRan || actionCalled != test.wantAction {
				t.Fatalf("execution = (ran %v, action %v), want (%v, %v)", ran, actionCalled, test.wantRan, test.wantAction)
			}
			if !errors.Is(gotActionErr, test.wantActionErr) {
				t.Fatalf("action error = %v, want %v", gotActionErr, test.wantActionErr)
			}
			if len(test.wantControlErrs) == 0 && gotControlErr != nil {
				t.Fatalf("control error = %v, want nil", gotControlErr)
			}
			for _, wantErr := range test.wantControlErrs {
				if !errors.Is(gotControlErr, wantErr) {
					t.Fatalf("control error = %v, want joined %v", gotControlErr, wantErr)
				}
			}
			if got, want := strings.Join(test.control.calls, ","), strings.Join(test.wantCalls, ","); got != want {
				t.Fatalf("calls = %q, want %q", got, want)
			}
		})
	}
}

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

func TestCgroupParentWritableByCallerRejectsCurrentAndRestorableAccess(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "cgroup.procs")
	if err := os.WriteFile(path, nil, 0400); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cgroup.procs test file has unknown ownership")
	}
	writable, err := cgroupParentWritableByCaller(parent, int(stat.Uid), int(stat.Gid))
	if err != nil || !writable {
		t.Fatalf("owner-restorable parent = (%v, %v), want (true, nil)", writable, err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	writable, err = cgroupParentWritableByCaller(parent, int(stat.Uid), int(stat.Gid))
	if err != nil || !writable {
		t.Fatalf("currently writable parent = (%v, %v), want (true, nil)", writable, err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = cgroupParentWritableByCaller(parent, int(stat.Uid), int(stat.Gid)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing migration file error = %v", err)
	}
}

func TestCgroupParentWritableByCallerRejectsInvalidIdentity(t *testing.T) {
	if writable, err := cgroupParentWritableByCaller(t.TempDir(), -1, 1); err == nil || !writable {
		t.Fatalf("invalid caller identity = (%v, %v), want (true, error)", writable, err)
	}
}

func TestCgroupParentWritableByIdentityChecksOwnerAndACLClasses(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "cgroup.procs")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cgroup.procs test file has unknown ownership")
	}
	owner := &tor.Identity{UID: stat.Uid, GID: stat.Gid}
	nonOwner := &tor.Identity{UID: stat.Uid + 1, GID: stat.Gid + 1}
	for _, test := range []struct {
		name string
		mode os.FileMode
		id   *tor.Identity
		want bool
	}{
		{name: "missing identity", mode: 0400, want: true},
		{name: "owner write", mode: 0600, id: owner, want: true},
		{name: "owner can add write", mode: 0400, id: owner, want: true},
		{name: "unrelated owner", mode: 0600, id: nonOwner},
		{name: "group or ACL class", mode: 0620, id: nonOwner, want: true},
		{name: "other class", mode: 0602, id: nonOwner, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			got, err := cgroupParentWritableByIdentity(parent, test.id)
			if err != nil || got != test.want {
				t.Fatalf("cgroupParentWritableByIdentity() = (%v, %v), want (%v, nil)", got, err, test.want)
			}
		})
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
