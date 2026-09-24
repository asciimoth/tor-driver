//go:build windows

package direct

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	tor "github.com/asciimoth/tor-driver"
)

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
	if err = process.Wait(); err != nil {
		t.Fatalf("contained probe failed: %v\n%s", err, strings.TrimSpace(output.String()))
	}
	if err = process.Release(); err != nil {
		t.Fatal(err)
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
