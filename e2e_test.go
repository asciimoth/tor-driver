//go:build e2e

package tordriver_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
	deps := direct.Dependencies(direct.Network(), out, testLogger{t: t})
	if path := os.Getenv("TOR_DRIVER_TEST_TORRC_FILE"); path != "" {
		extra, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		deps.FS = &testTorrcFS{FileSystem: deps.FS, extra: extra}
	}
	tracker := newRuntimeTracker(deps)
	d, err := tor.Start(ctx, cfg, tracker.dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
		tracker.assertClean(t)
	})
	return d
}

type testLogger struct{ t *testing.T }

func (l testLogger) Debug(args ...any)                 { l.t.Log(args...) }
func (l testLogger) Debugf(format string, args ...any) { l.t.Logf(format, args...) }
func (l testLogger) Info(args ...any)                  { l.t.Log(args...) }
func (l testLogger) Infof(format string, args ...any)  { l.t.Logf(format, args...) }
func (l testLogger) Warn(args ...any)                  { l.t.Log(args...) }
func (l testLogger) Warnf(format string, args ...any)  { l.t.Logf(format, args...) }
func (l testLogger) Err(args ...any)                   { l.t.Log(args...) }
func (l testLogger) Errf(format string, args ...any)   { l.t.Logf(format, args...) }
func (l testLogger) Fatal(args ...any)                 { l.t.Log(args...) }
func (l testLogger) Fatalf(format string, args ...any) { l.t.Logf(format, args...) }

// testTorrcFS is an e2e-only adapter. It lets a controlled test network add
// directory authorities without adding a raw torrc escape hatch to Config.
type testTorrcFS struct {
	tor.FileSystem
	extra []byte
}

func (f *testTorrcFS) WriteFile(path string, data []byte, mode fs.FileMode, owner *tor.Identity) error {
	if filepath.Base(path) == "torrc" {
		merged := make([]byte, 0, len(data)+len(f.extra)+2)
		merged = append(merged, data...)
		if len(merged) > 0 && merged[len(merged)-1] != '\n' {
			merged = append(merged, '\n')
		}
		merged = append(merged, f.extra...)
		if len(merged) > 0 && merged[len(merged)-1] != '\n' {
			merged = append(merged, '\n')
		}
		data = merged
	}
	return f.FileSystem.WriteFile(path, data, mode, owner)
}

type runtimeTracker struct {
	dependencies tor.Dependencies
	fs           *runtimeFS
	processes    *runtimeProcesses
	local        *runtimeNetwork
}

func newRuntimeTracker(deps tor.Dependencies) *runtimeTracker {
	fs := &runtimeFS{FileSystem: deps.FS}
	processes := &runtimeProcesses{Processes: deps.Processes}
	local := &runtimeNetwork{Network: deps.LocalNetwork}
	deps.FS = fs
	deps.Processes = processes
	deps.LocalNetwork = local
	return &runtimeTracker{dependencies: deps, fs: fs, processes: processes, local: local}
}
func (r *runtimeTracker) assertClean(t *testing.T) {
	t.Helper()
	for _, p := range r.processes.snapshot() {
		if !p.waited.Load() || !p.released.Load() {
			t.Errorf("Tor process cleanup: waited=%v released=%v", p.waited.Load(), p.released.Load())
		}
	}
	for _, path := range r.fs.snapshot() {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("temporary work directory remains: %s: %v", path, err)
		}
	}
	if active := r.local.active.Load(); active != 0 {
		t.Errorf("%d local sockets remain active", active)
	}
}

// Register this before other cleanups so it runs after all drivers and servers.
func trackGoroutines(t *testing.T) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(3 * time.Second)
		for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
			runtime.Gosched()
			time.Sleep(10 * time.Millisecond)
		}
		if after := runtime.NumGoroutine(); after > before+2 {
			t.Errorf("driver goroutines did not settle: before=%d after=%d", before, after)
		}
	})
}

type runtimeFS struct {
	tor.FileSystem
	mu    sync.Mutex
	paths []string
}

func (f *runtimeFS) TempDir(parent, pattern string) (string, error) {
	path, err := f.FileSystem.TempDir(parent, pattern)
	if err == nil {
		f.mu.Lock()
		f.paths = append(f.paths, path)
		f.mu.Unlock()
	}
	return path, err
}
func (f *runtimeFS) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

type runtimeProcesses struct {
	tor.Processes
	mu        sync.Mutex
	processes []*runtimeProcess
}

func (p *runtimeProcesses) Start(ctx context.Context, launch tor.Launch) (tor.Process, error) {
	process, err := p.Processes.Start(ctx, launch)
	if err != nil {
		return nil, err
	}
	tracked := &runtimeProcess{Process: process}
	p.mu.Lock()
	p.processes = append(p.processes, tracked)
	p.mu.Unlock()
	return tracked, nil
}
func (p *runtimeProcesses) snapshot() []*runtimeProcess {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*runtimeProcess(nil), p.processes...)
}

type runtimeProcess struct {
	tor.Process
	waited   atomic.Bool
	released atomic.Bool
}

func (p *runtimeProcess) Wait() error {
	err := p.Process.Wait()
	p.waited.Store(true)
	return err
}
func (p *runtimeProcess) Release() error {
	err := p.Process.Release()
	p.released.Store(true)
	return err
}

type runtimeNetwork struct {
	gonnect.Network
	active atomic.Int64
}

func (n *runtimeNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := n.Network.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	n.active.Add(1)
	return &runtimeConn{Conn: conn, closed: func() { n.active.Add(-1) }}, nil
}
func (n *runtimeNetwork) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	listener, err := n.Network.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	n.active.Add(1)
	return &runtimeListener{Listener: listener, network: n}, nil
}

type runtimeConn struct {
	net.Conn
	once   sync.Once
	closed func()
}

func (c *runtimeConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closed)
	return err
}

type runtimeListener struct {
	net.Listener
	network *runtimeNetwork
	once    sync.Once
}

func (l *runtimeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.network.active.Add(1)
	return &runtimeConn{Conn: conn, closed: func() { l.network.active.Add(-1) }}, nil
}
func (l *runtimeListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { l.network.active.Add(-1) })
	return err
}

// This really starts Tor, but supplies no external Network. No public Tor
// bootstrap is needed to exercise cookies, ownership and ADD/DEL_ONION.
func TestTorOfflineLifecycle(t *testing.T) {
	trackGoroutines(t)
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

func privateFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("TOR_DRIVER_PRIVATE") != "1" || os.Getenv("TOR_DRIVER_TEST_TORRC_FILE") == "" {
		t.Skip("run the private Tor network with ./e2e/run.sh")
	}
}

func localHTTPServer(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "private Tor e2e")
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func fetchHTTP(ctx context.Context, n gonnect.Network, url, want string) error {
	tr := &http.Transport{DialContext: n.Dial, Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		return err
	}
	if string(body) != want {
		return fmt.Errorf("unexpected response %q", body)
	}
	return nil
}

func retryHTTP(t *testing.T, ctx context.Context, n gonnect.Network, url, want string) {
	t.Helper()
	var last error
	for ctx.Err() == nil {
		if last = fetchHTTP(ctx, n, url, want); last == nil {
			return
		}
		if err := (direct.System{}).Sleep(ctx, time.Second); err != nil {
			break
		}
	}
	t.Fatalf("HTTP request through Tor failed: %v", last)
}

func obfs4Config(t *testing.T, cfg tor.Config) (tor.Config, string) {
	t.Helper()
	binary := os.Getenv("TOR_OBFS4_BINARY")
	address := os.Getenv("TOR_BRIDGE_ADDRESS")
	fingerprint := os.Getenv("TOR_BRIDGE_FINGERPRINT")
	certificate := os.Getenv("TOR_BRIDGE_CERT")
	if binary == "" || address == "" || fingerprint == "" || certificate == "" {
		t.Fatal("incomplete obfs4 test configuration")
	}
	cfg.UseBridges = true
	cfg.Transports = []tor.TransportConfig{{Kind: tor.Obfs4, Executable: binary}}
	cfg.Bridges = []tor.Bridge{{
		Transport:        tor.Obfs4,
		Address:          address,
		Fingerprint:      tor.Fingerprint(fingerprint),
		Obfs4Certificate: certificate,
	}}
	if _, err := netip.ParseAddrPort(address); err != nil {
		t.Fatal(err)
	}
	return cfg, address
}

func TestTorPrivateDirectExitAndOutboundReplacement(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	url := localHTTPServer(t)
	out := &countedNetwork{Network: direct.Network()}
	d := startDriver(t, ctx, torConfig(t), out)
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.IsolateEachConnection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	retryHTTP(t, ctx, n, url, "private Tor e2e")
	if out.attempts.Load() == 0 {
		t.Fatal("Tor did not use the injected outbound network")
	}

	if err = d.SetOutbound(nil); err != nil {
		t.Fatal(err)
	}
	target := strings.TrimPrefix(url, "http://")
	blocked, stop := context.WithTimeout(ctx, 3*time.Second)
	if conn, dialErr := n.Dial(blocked, "tcp", target); dialErr == nil {
		_ = conn.Close()
		stop()
		t.Fatal("Tor traffic survived egress removal")
	}
	stop()

	replacement := &countedNetwork{Network: direct.Network()}
	if err = d.SetOutbound(replacement); err != nil {
		t.Fatal(err)
	}
	if err = d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	retryHTTP(t, ctx, n, url, "private Tor e2e")
	if replacement.attempts.Load() == 0 {
		t.Fatal("Tor did not use the replacement outbound network")
	}
}

func TestTorPrivateObfs4Exit(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cfg, bridgeAddress := obfs4Config(t, torConfig(t))
	cfg.ForwardTorLogs = true
	out := &countedNetwork{Network: direct.Network(), allowed: bridgeAddress}
	d := startDriver(t, ctx, cfg, out)
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.IsolateEachConnection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	retryHTTP(t, ctx, n, localHTTPServer(t), "private Tor e2e")
	if out.attempts.Load() == 0 || out.unexpected.Load() {
		t.Fatal("obfs4 did not exclusively request the private bridge through the injected proxy")
	}
}

func TestTorOnionHTTPAndOutboundReplacement(t *testing.T) {
	if os.Getenv("TOR_DRIVER_LIVE") != "1" {
		t.Skip("set TOR_DRIVER_LIVE=1 to contact the public Tor network")
	}
	trackGoroutines(t)
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
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cfg, bridgeAddress := obfs4Config(t, torConfig(t))
	out := &countedNetwork{Network: direct.Network(), allowed: bridgeAddress}
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
