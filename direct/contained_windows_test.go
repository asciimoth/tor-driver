//go:build windows

package direct

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	tor "github.com/asciimoth/tor-driver"
)

func TestWindowsContainmentVerifiesEffectivePolicyAndCleansUp(t *testing.T) {
	var scripts []string
	runner := func(_ string, args ...string) ([]byte, error) {
		script := strings.Join(args, " ")
		scripts = append(scripts, script)
		if strings.Contains(script, "Get-NetFirewallProfile") {
			return []byte("firewall profile disabled"), errors.New("exit status 1")
		}
		return nil, nil
	}
	_, err := newContainedSystem(WindowsContainmentConfig{
		Executables:          []string{`C:\Tor\tor.exe`, `C:\Tor\lyrebird.exe`},
		PowerShellExecutable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}, runner)
	if err == nil || !strings.Contains(err.Error(), "verify Windows containment firewall") {
		t.Fatalf("newContainedSystem() error = %v", err)
	}
	joined := strings.Join(scripts, "\n")
	for _, required := range []string{"New-NetFirewallRule", "Get-NetFirewallProfile", "PolicyStore ActiveStore", "Remove-NetFirewallRule"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("PowerShell calls lack %q:\n%s", required, joined)
		}
	}
}

func TestWindowsContainmentRetainsFirewallUntilJobRelease(t *testing.T) {
	calls := 0
	s := &ContainedSystem{
		group:       "tor-driver-test",
		started:     true,
		executables: map[string]struct{}{},
		runner: func(string, ...string) ([]byte, error) {
			calls++
			return nil, nil
		},
	}
	if err := s.Close(); err == nil || !strings.Contains(err.Error(), "firewall retained") {
		t.Fatalf("Close() while running = %v", err)
	}
	if calls != 0 || s.closed {
		t.Fatalf("early Close removed firewall: calls=%d closed=%v", calls, s.closed)
	}
	underlying := &containmentTestProcess{}
	process := &containedProcess{Process: underlying, owner: s}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err == nil || !strings.Contains(err.Error(), "firewall retained") {
		t.Fatalf("Close() before Job release = %v", err)
	}
	if calls != 0 || s.closed {
		t.Fatalf("post-Wait Close removed firewall: calls=%d closed=%v", calls, s.closed)
	}
	if err := process.Release(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || underlying.releaseCalls != 1 || !s.closed {
		t.Fatalf("post-release state: firewall calls=%d release calls=%d closed=%v", calls, underlying.releaseCalls, s.closed)
	}
	if err := process.Release(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || underlying.releaseCalls != 1 {
		t.Fatalf("second Release repeated cleanup: firewall calls=%d release calls=%d", calls, underlying.releaseCalls)
	}
}

func TestWindowsContainmentRetainsFirewallWhenJobReleaseFails(t *testing.T) {
	firewallCalls := 0
	s := &ContainedSystem{
		group:   "tor-driver-test",
		started: true,
		runner: func(string, ...string) ([]byte, error) {
			firewallCalls++
			return nil, nil
		},
	}
	releaseErr := errors.New("release failed")
	underlying := &containmentTestProcess{releaseErr: releaseErr}
	process := &containedProcess{Process: underlying, owner: s}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	err := process.Release()
	if !errors.Is(err, releaseErr) || !strings.Contains(err.Error(), "firewall retained") {
		t.Fatalf("Release() error = %v", err)
	}
	if firewallCalls != 0 || s.closed || s.jobReleased {
		t.Fatalf("failed Job release removed firewall: calls=%d closed=%v released=%v", firewallCalls, s.closed, s.jobReleased)
	}
	if err = s.Close(); err == nil || !strings.Contains(err.Error(), "firewall retained") {
		t.Fatalf("Close() after failed Job release = %v", err)
	}
}

type containmentTestProcess struct {
	waitErr      error
	releaseErr   error
	releaseCalls int
}

func (p *containmentTestProcess) Wait() error { return p.waitErr }
func (p *containmentTestProcess) Kill() error { return nil }
func (p *containmentTestProcess) Release() error {
	p.releaseCalls++
	return p.releaseErr
}

var (
	containmentProbeLoopback = flag.String("containment-probe-loopback", "", "loopback TCP probe address")
	containmentProbeIPv4     = flag.String("containment-probe-ipv4", "", "external IPv4 TCP probe address")
	containmentProbeIPv6     = flag.String("containment-probe-ipv6", "", "external IPv6 TCP probe address")
	containmentProbeDNS      = flag.String("containment-probe-dns", "", "external UDP probe address")
)

func TestWindowsContainmentProbeHelper(t *testing.T) {
	if *containmentProbeLoopback == "" {
		return
	}
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.Dial("tcp", *containmentProbeLoopback)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loopback was blocked: %v\n", err)
		os.Exit(10)
	}
	_ = connection.Close()
	for name, address := range map[string]string{"IPv4": *containmentProbeIPv4, "IPv6": *containmentProbeIPv6} {
		connection, err = dialer.Dial("tcp", address)
		if err == nil {
			_ = connection.Close()
			fmt.Fprintf(os.Stderr, "%s escaped containment\n", name)
			os.Exit(11)
		}
	}
	connection, err = dialer.Dial("udp", *containmentProbeDNS)
	if err == nil {
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, writeErr := connection.Write([]byte("dns-probe"))
		var response [32]byte
		_, readErr := connection.Read(response[:])
		_ = connection.Close()
		if writeErr == nil && readErr == nil {
			fmt.Fprintln(os.Stderr, "UDP/DNS escaped containment")
			os.Exit(12)
		}
	}
	os.Exit(0)
}

func TestWindowsContainedSystemEnforcesNetworkBoundary(t *testing.T) {
	if os.Getenv("TOR_DRIVER_WINDOWS_CONTAINMENT") != "1" {
		t.Skip("set TOR_DRIVER_WINDOWS_CONTAINMENT=1 in the elevated Windows VM gate")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ipv4 := requiredProbeAddress(t, "TOR_DRIVER_WINDOWS_PROBE_IPV4")
	ipv6 := requiredProbeAddress(t, "TOR_DRIVER_WINDOWS_PROBE_IPV6")
	dns := requiredProbeAddress(t, "TOR_DRIVER_WINDOWS_PROBE_UDP")
	loopbackListener := listenTCP(t, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	serveTCP(t, loopbackListener)

	// Prove that each private host witness is reachable before firewall rules
	// are installed. The gate does not use the public network.
	probeTCP(t, ipv4)
	probeTCP(t, ipv6)
	probeUDP(t, dns)

	contained, err := NewContainedSystem(WindowsContainmentConfig{Executables: []string{executable}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := contained.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	})
	args := []string{
		"-test.run=^TestWindowsContainmentProbeHelper$",
		"-containment-probe-loopback=" + loopbackListener.Addr().String(),
		"-containment-probe-ipv4=" + ipv4,
		"-containment-probe-ipv6=" + ipv6,
		"-containment-probe-dns=" + dns,
	}
	var output bytes.Buffer
	process, err := contained.Start(context.Background(), tor.Launch{Executable: executable, Args: args, Stdout: &output, Stderr: &output})
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := contained.Close(); closeErr == nil || !strings.Contains(closeErr.Error(), "firewall retained") {
		t.Fatalf("Close() did not retain the firewall for a running process: %v", closeErr)
	}
	if err = process.Wait(); err != nil {
		t.Fatalf("contained probe failed: %v\n%s", err, strings.TrimSpace(output.String()))
	}
	if closeErr := contained.Close(); closeErr == nil || !strings.Contains(closeErr.Error(), "firewall retained") {
		t.Fatalf("Close() removed the firewall before Job release: %v", closeErr)
	}
	if err = process.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsContainedSystemRejectsDisabledFirewall(t *testing.T) {
	if os.Getenv("TOR_DRIVER_WINDOWS_CONTAINMENT") != "1" {
		t.Skip("set TOR_DRIVER_WINDOWS_CONTAINMENT=1 in the elevated Windows VM gate")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal(err)
	}
	profile := func(script string) string {
		t.Helper()
		output, runErr := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if runErr != nil {
			t.Fatalf("PowerShell failed: %v: %s", runErr, output)
		}
		return strings.TrimSpace(string(output))
	}
	original := profile(`(Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore).Enabled`)
	if original != "True" {
		t.Fatalf("Public firewall profile must start enabled, got %q", original)
	}
	t.Cleanup(func() { profile(`Set-NetFirewallProfile -Name Public -Enabled True`) })
	profile(`Set-NetFirewallProfile -Name Public -Enabled False`)
	contained, err := NewContainedSystem(WindowsContainmentConfig{Executables: []string{executable}})
	if contained != nil {
		_ = contained.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "verify Windows containment firewall") {
		t.Fatalf("NewContainedSystem() with disabled firewall error = %v", err)
	}
}

func requiredProbeAddress(t *testing.T, name string) string {
	t.Helper()
	address := os.Getenv(name)
	if address == "" {
		t.Fatalf("%s is not set", name)
	}
	return address
}

func listenTCP(t *testing.T, address *net.TCPAddr) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func serveTCP(t *testing.T, listener *net.TCPListener) {
	t.Helper()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
}

func probeTCP(t *testing.T, address string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("preflight TCP probe %s: %v", address, err)
	}
	_ = connection.Close()
}

func probeUDP(t *testing.T, address string) {
	t.Helper()
	connection, err := net.DialTimeout("udp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("preflight")); err != nil {
		t.Fatal(err)
	}
	var response [32]byte
	if _, err = connection.Read(response[:]); err != nil {
		t.Fatal(err)
	}
}
