//go:build e2e

package tordriver_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gobox"
	"github.com/asciimoth/gobox/debug"
	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

type testClock struct{}

func (testClock) Now() time.Time { return time.Now() }
func (testClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (testClock) Timeout(ctx context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, duration)
}

type testLogger struct{ t *testing.T }

func (logger testLogger) Debug(args ...any)                 { logger.t.Log(args...) }
func (logger testLogger) Debugf(format string, args ...any) { logger.t.Logf(format, args...) }
func (logger testLogger) Info(args ...any)                  { logger.t.Log(args...) }
func (logger testLogger) Infof(format string, args ...any)  { logger.t.Logf(format, args...) }
func (logger testLogger) Warn(args ...any)                  { logger.t.Log(args...) }
func (logger testLogger) Warnf(format string, args ...any)  { logger.t.Logf(format, args...) }
func (logger testLogger) Err(args ...any)                   { logger.t.Log(args...) }
func (logger testLogger) Errf(format string, args ...any)   { logger.t.Logf(format, args...) }
func (logger testLogger) Fatal(args ...any)                 { logger.t.Log(args...) }
func (logger testLogger) Fatalf(format string, args ...any) { logger.t.Logf(format, args...) }

func startTestTor(t *testing.T, ctx context.Context, cfg tor.Config, outbound gonnect.Network) *tor.Driver {
	t.Helper()
	executable := os.Getenv("TOR_BINARY")
	if executable == "" {
		var err error
		executable, err = exec.LookPath("tor")
		if err != nil {
			t.Skip("real Tor not installed; set TOR_BINARY")
		}
	}
	boxConfig := debug.Config{
		Programs: map[gobox.ProgramID]debug.Program{
			tor.DefaultTorProgram: {
				Executable: executable,
				Arguments: func(launch gobox.Launch, resolve debug.ResolveValue) ([]string, error) {
					defaults, ok := launch.Inputs["defaults-torrc"]
					if !ok {
						return nil, fmt.Errorf("missing defaults-torrc")
					}
					torrc, ok := launch.Inputs["torrc"]
					if !ok {
						return nil, fmt.Errorf("missing torrc")
					}
					defaultsPath, err := resolve(defaults)
					if err != nil {
						return nil, err
					}
					torrcPath, err := resolve(torrc)
					if err != nil {
						return nil, err
					}
					return []string{"--defaults-torrc", defaultsPath, "-f", torrcPath}, nil
				},
			},
		},
		Templates: map[gobox.TemplateID]debug.Template{
			tor.DefaultSandboxTemplate: {Programs: []gobox.ProgramID{tor.DefaultTorProgram}},
		},
	}
	for _, method := range cfg.Transports {
		if method.Program == "" {
			continue
		}
		program := os.Getenv("TOR_OBFS4_BINARY")
		if program == "" {
			var err error
			program, err = exec.LookPath("lyrebird")
			if err != nil {
				t.Skip("install lyrebird or set TOR_OBFS4_BINARY")
			}
		}
		boxConfig.Programs[method.Program] = debug.Program{Executable: program}
		template := boxConfig.Templates[tor.DefaultSandboxTemplate]
		template.Programs = append(template.Programs, method.Program)
		boxConfig.Templates[tor.DefaultSandboxTemplate] = template
	}
	backend, err := debug.New(boxConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})

	_, sandboxes, err := backend.IssueAndBindOwner(ctx, gobox.Owner{Workspace: "tor-driver-tests", Class: "e2e", Name: t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := tor.Start(ctx, cfg, tor.Dependencies{
		Sandboxes: sandboxes,
		Clock:     testClock{},
		Random:    rand.Reader,
		Logger:    testLogger{t},
		Outbound:  outbound,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := driver.Close(); err != nil {
			t.Error(err)
		}
	})
	return driver
}

func TestTorThroughDebugGoboxBackend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	driver := startTestTor(t, ctx, tor.Config{}, gonnect.NativeConfig{}.Build())
	if err := driver.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}

type recordingNetwork struct {
	gonnect.RejectNetwork
	requests chan string
}

func (n *recordingNetwork) Dial(ctx context.Context, _, address string) (net.Conn, error) {
	select {
	case n.requests <- address:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, io.EOF
}

// Exercise the actual bridge requests from Tor. The injected network has no
// route to the Internet. Transport callbacks record their selection by dialing
// a distinct test destination through the supplied outbound dialer.
func TestTorBridgeTransports(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	n := &recordingNetwork{requests: make(chan string, 256)}
	handler := func(method string) tor.TransportDial {
		return func(ctx context.Context, address string, args map[string]string, dial tor.OutboundDial) (net.Conn, error) {
			return dial(ctx, "tcp", method+" "+address+" "+args["mode"])
		}
	}
	bridges := []tor.Bridge{
		{Transport: "sample", Address: "192.0.2.1:443", Args: map[string]string{"mode": "first"}},
		{Transport: "sample", Address: "192.0.2.2:443", Args: map[string]string{"mode": "second"}},
		{Transport: "other", Address: "[2001:db8::3]:443", Args: map[string]string{"mode": "third"}},
		{Address: "192.0.2.4:443"},
	}
	cfg := tor.Config{StateDirectory: gobox.Path{Root: gobox.Persistent, Rel: "state"}, ClientIP: tor.ClientPreferIPv6, UseBridges: true, Bridges: bridges, Transports: []tor.TransportConfig{{Kind: "sample", Dial: handler("sample")}, {Kind: "other", Dial: handler("other")}}}
	d := startTestTor(t, ctx, cfg, n)
	expected := map[string]bool{"sample 192.0.2.1:443 first": true, "sample 192.0.2.2:443 second": true, "other [2001:db8::3]:443 third": true, "192.0.2.4:443": true}
	seen := map[string]bool{}
	for len(seen) != len(expected) {
		select {
		case s := <-n.requests:
			if !expected[s] {
				t.Fatalf("unexpected dial %q", s)
			}
			seen[s] = true
		case <-ctx.Done():
			t.Fatalf("startup requests: %v", seen)
		}
	}
	bridges[0].Args["mode"] = "replacement"
	if err := d.SetBridges(ctx, tor.BridgeConfig{UseBridges: true, Bridges: bridges[:1]}); err != nil {
		t.Fatal(err)
	}
replacement:
	for {
		select {
		case s := <-n.requests:
			if s == "sample 192.0.2.1:443 replacement" {
				break replacement
			}
			if !expected[s] {
				t.Fatalf("unexpected replacement dial %q", s)
			}
		case <-ctx.Done():
			t.Fatal("no updated bridge request")
		}
	}
	if err := d.SetBridges(ctx, tor.BridgeConfig{}); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case s := <-n.requests:
			if s == "sample 192.0.2.1:443 replacement" {
				continue
			}
			ap, err := netip.ParseAddrPort(s)
			if err != nil || netip.MustParsePrefix("192.0.2.0/24").Contains(ap.Addr()) || ap.Addr().IsLoopback() {
				t.Fatalf("unexpected direct-mode request %q", s)
			}
			return
		case <-ctx.Done():
			t.Fatal("no ordinary relay request")
		}
	}
}

func TestTorBridgeTransportsManaged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n := &recordingNetwork{requests: make(chan string, 256)}
	bridge := tor.Bridge{Transport: "obfs4", Address: "192.0.2.17:443", Fingerprint: tor.Fingerprint(strings.Repeat("A", 40)), Args: map[string]string{"cert": base64.RawStdEncoding.EncodeToString(make([]byte, 52)), "iat-mode": "0"}}
	d := startTestTor(t, ctx, tor.Config{UseBridges: true, Bridges: []tor.Bridge{bridge}, Transports: []tor.TransportConfig{{Kind: "obfs4", Program: "lyrebird"}}}, n)
	select {
	case address := <-n.requests:
		if address != bridge.Address {
			t.Fatalf("managed transport dialed %q", address)
		}
	case <-ctx.Done():
		t.Fatal("managed transport did not use the outbound proxy")
	}
	if err := d.SetBridges(ctx, tor.BridgeConfig{}); err != nil {
		t.Fatal(err)
	}
	bridge.Address = "192.0.2.18:443"
	if err := d.SetBridges(ctx, tor.BridgeConfig{UseBridges: true, Bridges: []tor.Bridge{bridge}}); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case address := <-n.requests:
			if address == bridge.Address {
				return
			}
		case <-ctx.Done():
			t.Fatal("reactivated managed transport did not dial the replacement bridge")
		}
	}
}

type bridgeStreamNetwork struct {
	gonnect.RejectNetwork
	peer chan net.Conn
}

func (n *bridgeStreamNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != "192.0.2.15:443" {
		return nil, fmt.Errorf("unexpected dial %s %s", network, address)
	}
	conn, peer := net.Pipe()
	select {
	case n.peer <- peer:
		return conn, nil
	case <-ctx.Done():
		_ = conn.Close()
		_ = peer.Close()
		return nil, ctx.Err()
	}
}

func TestTorBridgeTransportsStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	outbound := &bridgeStreamNetwork{peer: make(chan net.Conn, 1)}
	handshake := func(ctx context.Context, addr string, args map[string]string, dial tor.OutboundDial) (net.Conn, error) {
		c, err := dial(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		_, err = io.WriteString(c, args["greeting"])
		return c, err
	}
	cfg := tor.Config{UseBridges: true, Bridges: []tor.Bridge{{Address: "192.0.2.15:443", Transport: "stream", Args: map[string]string{"greeting": "hello"}}}, Transports: []tor.TransportConfig{{Kind: "stream", Dial: handshake}}}
	startTestTor(t, ctx, cfg, outbound)
	select {
	case peer := <-outbound.peer:
		defer func() { _ = peer.Close() }()
		deadline, _ := ctx.Deadline()
		if err := peer.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		// The transport writes its greeting, then Tor writes the TLS handshake
		// record (22) containing its ClientHello (1).
		var data [11]byte
		if _, err := io.ReadFull(peer, data[:]); err != nil {
			t.Fatal(err)
		}
		if string(data[:5]) != "hello" || data[5] != 22 || data[10] != 1 {
			t.Fatalf("unexpected stream prefix %x", data)
		}
	case <-ctx.Done():
		t.Fatal("no bridge connection")
	}
}
