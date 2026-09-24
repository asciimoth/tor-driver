//go:build windows

package direct

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

func TestWindowsContainedSystemFailsClosedForEveryConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  WindowsContainmentConfig
	}{
		{name: "empty"},
		{name: "one executable", cfg: WindowsContainmentConfig{Executables: []string{`C:\Tor\tor.exe`}}},
		{name: "Tor and transport", cfg: WindowsContainmentConfig{Executables: []string{`C:\Tor\tor.exe`, `C:\Tor\lyrebird.exe`}}},
		{name: "explicit PowerShell", cfg: WindowsContainmentConfig{Executables: []string{`C:\Tor\tor.exe`}, PowerShellExecutable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system, err := NewContainedSystem(test.cfg)
			if system != nil || !errors.Is(err, tor.ErrUnsupported) {
				t.Fatalf("NewContainedSystem() = (%v, %v), want (nil, ErrUnsupported)", system, err)
			}
		})
	}
}

func TestWindowsContainedSystemFailsClosedWithoutFirewallMutation(t *testing.T) {
	if os.Getenv("TOR_DRIVER_WINDOWS_CONTAINMENT") != "1" {
		t.Skip("set TOR_DRIVER_WINDOWS_CONTAINMENT=1 in the elevated Windows VM gate")
	}
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal(err)
	}
	countRules := func() int {
		t.Helper()
		const script = `@((Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop) | Where-Object { [string]$_.DisplayGroup -like 'tor-driver-*' }).Count`
		output, runErr := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if runErr != nil {
			t.Fatalf("list containment firewall rules: %v: %s", runErr, output)
		}
		count, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
		if parseErr != nil {
			t.Fatalf("parse containment firewall rule count %q: %v", output, parseErr)
		}
		return count
	}
	before := countRules()
	system, err := NewContainedSystem(WindowsContainmentConfig{Executables: []string{`C:\Tor\tor.exe`, `C:\Tor\copied-tor.exe`}})
	if system != nil || !errors.Is(err, tor.ErrUnsupported) {
		t.Fatalf("NewContainedSystem() = (%v, %v), want (nil, ErrUnsupported)", system, err)
	}
	if after := countRules(); after != before {
		t.Fatalf("containment firewall rule count changed from %d to %d", before, after)
	}
}

func TestWindowsContainedSystemZeroValueCannotLaunch(t *testing.T) {
	system := &ContainedSystem{}
	process, err := system.Start(context.Background(), tor.Launch{Executable: `C:\Tor\tor.exe`})
	if process != nil || !errors.Is(err, tor.ErrUnsupported) {
		t.Fatalf("Start() = (%v, %v), want (nil, ErrUnsupported)", process, err)
	}
	deps := system.Dependencies(nil, nil, nil)
	if deps.Processes != system {
		t.Fatal("Dependencies did not retain the fail-closed process adapter")
	}
	if err = system.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func TestWindowsBestEffortReportsStrictContainmentUnavailable(t *testing.T) {
	cfg := tor.Config{TorExecutable: `C:\Tor\tor.exe`}
	resolved, processes, closeProcess, report, err := prepareBestEffort(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.TorExecutable != cfg.TorExecutable || closeProcess != nil {
		t.Fatalf("best-effort selection = (%+v, close function present: %t)", resolved, closeProcess != nil)
	}
	if _, ok := processes.(System); !ok {
		t.Fatalf("fallback processes type = %T, want System", processes)
	}
	if report.Containment || !errors.Is(report.ContainmentError, tor.ErrUnsupported) {
		t.Fatalf("fallback report = %+v", report)
	}
}
