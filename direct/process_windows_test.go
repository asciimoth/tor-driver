//go:build windows

package direct

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tor "github.com/asciimoth/tor-driver"
	"golang.org/x/sys/windows"
)

var (
	processHelperMode = flag.String("direct-process-helper", "", "run the Windows process test helper")
	processHelperPath = flag.String("direct-process-helper-path", "", "write the Windows helper PID to this path")
)

func TestWindowsProcessHelper(t *testing.T) {
	mode, path := *processHelperMode, *processHelperPath
	if mode == "" {
		return
	}
	switch mode {
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestWindowsProcessHelper$", "-direct-process-helper=child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(path, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			_ = child.Process.Kill()
			os.Exit(3)
		}
		_ = child.Wait()
	case "child":
		for {
			time.Sleep(time.Hour)
		}
	default:
		os.Exit(4)
	}
}

func TestProcessAdapterKillsDescendantsAndReleasesOnce(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	system := System{}
	process, err := system.Start(context.Background(), tor.Launch{
		Executable: executable,
		Args: []string{
			"-test.run=^TestWindowsProcessHelper$",
			"-direct-process-helper=parent",
			"-direct-process-helper-path=" + pidFile,
		},
		Directory: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Kill()
		_ = process.Release()
	})

	descendantPID := waitForHelperPID(t, pidFile)
	if err = process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = process.Wait(); err == nil {
		t.Fatal("killed process returned no wait error")
	}
	if err = process.Release(); err != nil {
		t.Fatal(err)
	}
	if err = process.Release(); err != nil {
		t.Fatalf("second Release() = %v", err)
	}
	waitForProcessExit(t, descendantPID)
}

func TestProcessAdapterRejectsLinuxIdentityBeforeStart(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "must-not-start.exe")
	_, err := (System{}).Start(context.Background(), tor.Launch{
		Executable: missing,
		Identity:   &tor.Identity{UID: 1, GID: 1},
	})
	if err == nil || !strings.Contains(err.Error(), "not supported on Windows") {
		t.Fatalf("Start() error = %v", err)
	}
	if _, statErr := os.Stat(missing); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unexpected executable state: %v", statErr)
	}
}

func waitForHelperPID(t *testing.T, path string) uint32 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.ParseUint(string(data), 10, 32)
			if parseErr != nil {
				t.Fatalf("parse helper PID: %v", parseErr)
			}
			return uint32(pid)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("helper descendant did not start")
	return 0
}

func waitForProcessExit(t *testing.T, pid uint32) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return
		}
		if err != nil {
			t.Fatalf("inspect descendant %d: %v", pid, err)
		}
		var code uint32
		err = windows.GetExitCodeProcess(handle, &code)
		_ = windows.CloseHandle(handle)
		if err != nil {
			t.Fatal(err)
		}
		if code != uint32(windows.STATUS_PENDING) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("descendant process %d still runs after Job termination", pid)
}
