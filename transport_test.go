package tordriver

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/socksgo"
)

func passthrough(ctx context.Context, addr string, _ map[string]string, dial OutboundDial) (net.Conn, error) {
	return dial(ctx, "tcp", addr)
}

func TestTransportConfiguration(t *testing.T) {
	cfg := Config{UseBridges: true, Transports: []TransportConfig{{Kind: "custom", Dial: passthrough}, {Kind: "managed", Program: "program"}}, Bridges: []Bridge{
		{Transport: "managed", Address: "[2001:db8::1]:443", Fingerprint: Fingerprint(strings.Repeat("a", 40)), Args: map[string]string{"z": "a=b;c", "a": ""}},
		{Transport: "custom", Address: "192.0.2.1:443", Args: map[string]string{"option": "two words\n#value"}},
		{Address: "192.0.2.2:9001"},
	}}
	validated, err := validate(cfg, configDeps())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bridges[0].Args["a"] = "changed"
	if got := bridgeLines(validated.Bridges[:1])[0]; got != "managed [2001:db8::1]:443 "+strings.Repeat("a", 40)+" a= z=a=b;c" {
		t.Fatal(got)
	}
	for _, registration := range []TransportConfig{
		{Dial: passthrough},
		{Kind: "x-y", Program: "x"},
		{Kind: "9method", Dial: passthrough},
		{Kind: "both", Program: "x", Dial: passthrough},
		{Kind: "missing"},
		{Kind: "custom", Program: "x"},
	} {
		bad := cfg
		bad.Transports = append(bad.Transports, registration)
		if _, err := validate(bad, configDeps()); err == nil {
			t.Fatalf("accepted registration %q", registration.Kind)
		}
	}
	for _, b := range []Bridge{
		{Address: "192.0.2.1:80", Args: map[string]string{"a": "b"}},
		{Transport: "managed", Address: "192.0.2.1:80", Args: map[string]string{"x": "#"}},
		{Transport: "managed", Address: "192.0.2.1:80", Args: map[string]string{"x": strings.Repeat(";", 255)}},
		{Transport: "custom", Address: "192.0.2.1:80", Args: map[string]string{"a=b": "c"}},
	} {
		bad := cfg
		bad.Bridges = []Bridge{b}
		if _, err := validate(bad, configDeps()); err == nil {
			t.Fatalf("accepted bridge %#v", b)
		}
	}
}

func TestTransportSessionLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "handshake_failure", "pending", "nil_stream"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t, "")
			f.deps.Clock = fixtureClock{timeout: 4 * time.Second}
			peers := make(chan net.Conn, 4)
			f.deps.Outbound = &dialNetwork{dial: func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "192.0.2.7:443" {
					return nil, errors.New("unexpected destination")
				}
				a, b := net.Pipe()
				peers <- b
				return a, nil
			}}
			called := make(chan struct{}, 2)
			f.cfg.Transports = []TransportConfig{{Kind: "sample", Dial: func(ctx context.Context, address string, args map[string]string, dial OutboundDial) (net.Conn, error) {
				if args["mode"] != mode {
					return nil, errors.New("unexpected args")
				}
				args["mode"] = "mutated"
				c, err := dial(ctx, "tcp", address)
				if err != nil {
					return nil, err
				}
				// This stream belongs to the same session as the returned stream.
				if _, err := dial(ctx, "tcp", address); err != nil {
					return nil, err
				}
				called <- struct{}{}
				switch mode {
				case "handshake_failure":
					return c, errors.New("handshake failed")
				case "nil_stream":
					return nil, nil
				case "pending":
					<-ctx.Done()
					return c, ctx.Err()
				default:
					return c, nil
				}
			}}}
			b := Bridge{Transport: "sample", Address: "192.0.2.7:443", Args: map[string]string{"mode": mode}}
			f.cfg.UseBridges = true
			f.cfg.Bridges = []Bridge{b}
			d, err := Start(context.Background(), f.cfg, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = d.Close() }()
			b.Args["mode"] = "changed by caller"
			client, err := socksgo.ClientFromURL("socks5://" + string(d.proxy.user) + ":" + string(d.proxy.password) + "@" + d.proxy.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			client.Filter = func(string, string) bool { return false }
			route := d.cfg.Bridges[0].route
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			type result struct {
				c   net.Conn
				err error
			}
			done := make(chan result, 1)
			go func() {
				c, err := client.Dial(ctx, "tcp", route)
				done <- result{c, err}
			}()
			select {
			case <-called:
			case <-ctx.Done():
				t.Fatal("handler was not called")
			}
			peer, auxiliary := <-peers, <-peers
			defer func() { _ = auxiliary.Close() }()
			defer func() { _ = peer.Close() }()
			if mode == "pending" {
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
			}
			res := <-done
			if mode == "success" {
				if res.err != nil {
					t.Fatal(res.err)
				}
				defer func() { _ = res.c.Close() }()
				_ = res.c.SetDeadline(time.Now().Add(time.Second))
				go func() { _, _ = peer.Write([]byte("stream")) }()
				data := make([]byte, 6)
				if _, err := io.ReadFull(res.c, data); err != nil || string(data) != "stream" {
					t.Fatalf("read %q: %v", data, err)
				}
				if err := d.SetOutbound(nil); err != nil {
					t.Fatal(err)
				}
			} else if res.err == nil {
				t.Fatal("SOCKS client accepted failed handshake")
			}
			assertClosed(t, peer)
			assertClosed(t, auxiliary)
			if d.OutboundState().Attempts != 2 {
				t.Fatalf("unexpected fallback dial: %+v", d.OutboundState())
			}
		})
	}
}

func TestBridgeRelayAddressPreference(t *testing.T) {
	f := newLifecycleFixture(t, "")
	f.cfg.ClientIP = ClientPreferIPv6
	f.cfg.UseBridges = true
	f.cfg.Transports = []TransportConfig{{Kind: "sample", Dial: passthrough}}
	f.cfg.Bridges = []Bridge{{Transport: "sample", Address: "192.0.2.7:443"}}
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	path, err := d.box.ChildPath(d.work)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.fs.text(filepath.Join(path, "torrc")), "ClientPreferIPv6ORPort auto\n") {
		t.Fatal("startup did not select the configured bridge address family")
	}
	checkCommand := func(want string) {
		t.Helper()
		for _, line := range slices.Backward(f.processes.commandLines()) {
			if strings.HasPrefix(line, "SETCONF UseBridges=") {
				if !strings.Contains(line, " ClientPreferIPv6ORPort="+want+" ") {
					t.Fatalf("bridge change has wrong address preference: %s", line)
				}
				return
			}
		}
		t.Fatal("missing bridge change")
	}
	f.processes.rejectNextNetworkEnable()
	if err := d.SetBridges(context.Background(), BridgeConfig{}); err == nil {
		t.Fatal("accepted failed update")
	}
	checkCommand("auto")
	if err := d.SetBridges(context.Background(), BridgeConfig{}); err != nil {
		t.Fatal(err)
	}
	checkCommand("1")
	if err := d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: f.cfg.Bridges}); err != nil {
		t.Fatal(err)
	}
	checkCommand("auto")
}

func TestTransportRouteRollback(t *testing.T) {
	f := newLifecycleFixture(t, "")
	b := Bridge{Transport: "sample", Address: "[2001:db8::1]:443", Fingerprint: Fingerprint(strings.Repeat("1", 40)), Args: map[string]string{"x": "first"}}
	f.cfg.Transports = []TransportConfig{{Kind: "sample", Dial: passthrough}}
	f.cfg.UseBridges = true
	f.cfg.Bridges = []Bridge{b}
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	old := d.cfg.Bridges[0].route
	if line := bridgeLines(d.cfg.Bridges)[0]; line != old+" "+string(b.Fingerprint) {
		t.Fatal(line)
	}
	b.Args["x"] = "second"
	f.processes.rejectNextNetworkEnable()
	if err := d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{b}}); err == nil {
		t.Fatal("accepted failed update")
	}
	if routes := d.gate.routes; len(routes) != 1 || routes[old].bridge.Args["x"] != "first" {
		t.Fatal("old route not restored")
	}
	if err := d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{b}}); err != nil {
		t.Fatal(err)
	}
	if d.cfg.Bridges[0].route == old {
		t.Fatal("reused obsolete route")
	}
	if err := d.SetOutbound(&dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("retired route reached outbound")
		return nil, nil
	}}); err != nil {
		t.Fatal(err)
	}
	a, peer := net.Pipe()
	defer func() { _ = a.Close(); _ = peer.Close() }()
	for _, address := range []string{old, "[::ffff:127.128.0.1]:443"} {
		if _, _, err := d.gate.dial(context.Background(), a, address); !errors.Is(err, ErrUnsupportedTransport) {
			t.Fatalf("retired or reserved route %s: %v", address, err)
		}
	}
	err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{{Address: "[::ffff:127.128.0.1]:443"}}})
	if err == nil {
		t.Fatal("accepted mapped address in reserved transport range")
	}
}

// A network may return a stream after its attachment has been retired.
// The transport must see an error and the peer must observe closure.
func TestTransportLateOutbound(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	lower, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	g := &outboundGate{reserveRoutes: true, routes: map[string]bridgeRoute{"127.128.0.1:443": {bridge: Bridge{Address: "192.0.2.1:443"}, dial: passthrough}}}
	if err := g.replace(&dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		close(started)
		<-release
		return lower, nil
	}}); err != nil {
		t.Fatal(err)
	}
	inc, client := net.Pipe()
	defer func() { _ = client.Close() }()
	result := make(chan error, 1)
	go func() { _, _, err := g.dial(context.Background(), inc, "127.128.0.1:443"); result <- err }()
	<-started
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("late stream accepted")
	}
	assertClosed(t, peer)
	assertClosed(t, client)
}
