//go:build e2e

package tordriver_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
)

func torConfig(t *testing.T) tor.Config {
	t.Helper()
	path := os.Getenv("TOR_BINARY")
	if path == "" {
		var err error
		path, err = exec.LookPath("tor")
		if err != nil {
			t.Skip("real Tor not installed; set TOR_BINARY")
		}
	}
	path, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tor.Config{TorExecutable: path}
	if os.Getenv("TOR_TEST_UID") != "" {
		uid, e1 := strconv.ParseUint(os.Getenv("TOR_TEST_UID"), 10, 32)
		gid, e2 := strconv.ParseUint(os.Getenv("TOR_TEST_GID"), 10, 32)
		if e1 != nil || e2 != nil {
			t.Fatal("invalid TOR_TEST_UID/TOR_TEST_GID")
		}
		cfg.Identity = &tor.Identity{UID: uint32(uid), GID: uint32(gid)}
	}
	return cfg
}
func startDriver(t *testing.T, ctx context.Context, cfg tor.Config, out gonnect.Network) *tor.Driver {
	t.Helper()
	d, err := tor.Start(ctx, cfg, direct.Dependencies(direct.Network(), out, tor.NopLogger{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	return d
}

// This really starts Tor, but supplies no external Network. No public Tor
// bootstrap is needed to exercise cookies, ownership and ADD/DEL_ONION.
func TestTorOfflineLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := startDriver(t, ctx, torConfig(t), nil)
	if d.OutboundState().Available {
		t.Fatal("nil egress was not blocked")
	}
	n, err := d.NewNetwork(tor.NetworkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_ = n.Close()
	service, err := d.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80, 8080}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := service.Listen(ctx, "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(l.Addr().String(), service.Address()) {
		t.Fatal("listener did not report onion address")
	}
	if _, err = service.Listen(ctx, "tcp", ":80"); err == nil {
		t.Fatal("duplicate listener accepted")
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Accept(); err == nil {
		t.Fatal("service listener survived Close")
	}
	if err = d.SetOutbound(nil); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.Done():
	default:
		t.Fatal("driver has not finished shutdown")
	}
}

type countedNetwork struct {
	gonnect.Network
	attempts   atomic.Uint64
	allowed    string
	unexpected atomic.Bool
}

func (n *countedNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	n.attempts.Add(1)
	if n.allowed != "" && address != n.allowed {
		n.unexpected.Store(true)
		return nil, fmt.Errorf("unexpected Tor destination")
	}
	return n.Network.Dial(ctx, network, address)
}

func TestTorOnionHTTPAndOutboundReplacement(t *testing.T) {
	if os.Getenv("TOR_DRIVER_LIVE") != "1" {
		t.Skip("set TOR_DRIVER_LIVE=1 to contact the public Tor network")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cfg := torConfig(t)
	serverOut := &countedNetwork{Network: direct.Network()}
	clientOut := &countedNetwork{Network: direct.Network()}
	server := startDriver(t, ctx, cfg, serverOut)
	client := startDriver(t, ctx, cfg, clientOut)
	if err := server.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := server.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Listen(ctx, "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	h := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, "onion e2e") }), ReadHeaderTimeout: 10 * time.Second}
	defer func() { _ = h.Close() }()
	go func() { _ = h.Serve(l) }()
	n, err := client.NewNetwork(tor.NetworkConfig{Circuits: tor.IsolateEachConnection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	fetch := func() error {
		tr := &http.Transport{DialContext: n.Dial, Proxy: nil, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+s.Address()+"/", nil)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
		if err != nil {
			return err
		}
		if string(body) != "onion e2e" {
			return fmt.Errorf("unexpected response %q", body)
		}
		return nil
	}
	retry := func() {
		t.Helper()
		for {
			if err := fetch(); err == nil {
				return
			}
			if err := (direct.System{}).Sleep(ctx, time.Second); err != nil {
				t.Fatal(err)
			}
		}
	}
	retry()
	if serverOut.attempts.Load() == 0 || clientOut.attempts.Load() == 0 {
		t.Fatal("Tor did not use injected outbound networks")
	}
	if err = client.SetOutbound(nil); err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 3*time.Second)
	if c, e := n.Dial(blocked, "tcp", s.Address()+":80"); e == nil {
		_ = c.Close()
		stop()
		t.Fatal("Tor traffic survived egress removal")
	}
	stop()
	replacement := &countedNetwork{Network: direct.Network()}
	if err = client.SetOutbound(replacement); err != nil {
		t.Fatal(err)
	}
	if err = client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	retry()
	if replacement.attempts.Load() == 0 {
		t.Fatal("replacement network not used")
	}
}

func TestTorObfs4UsesInjectedProxy(t *testing.T) {
	if os.Getenv("TOR_DRIVER_LIVE") != "1" || os.Getenv("TOR_OBFS4_BINARY") == "" {
		t.Skip("requires TOR_DRIVER_LIVE=1 and configured obfs4 bridge; see docs/TESTING.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cfg := torConfig(t)
	cfg.UseBridges = true
	cfg.Transports = []tor.TransportConfig{{Kind: tor.Obfs4, Executable: os.Getenv("TOR_OBFS4_BINARY")}}
	cfg.Bridges = []tor.Bridge{{Transport: tor.Obfs4, Address: os.Getenv("TOR_BRIDGE_ADDRESS"), Fingerprint: tor.Fingerprint(os.Getenv("TOR_BRIDGE_FINGERPRINT")), Obfs4Certificate: os.Getenv("TOR_BRIDGE_CERT")}}
	bridge, err := netip.ParseAddrPort(cfg.Bridges[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	out := &countedNetwork{Network: direct.Network(), allowed: bridge.String()}
	d := startDriver(t, ctx, cfg, out)
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if out.attempts.Load() == 0 || out.unexpected.Load() {
		t.Fatal("obfs4 did not exclusively request the configured bridge via the injected proxy")
	}
	if err := d.SetOutbound(nil); err != nil {
		t.Fatal(err)
	}
}
