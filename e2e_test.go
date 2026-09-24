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
	return startDriverWithDependencies(t, ctx, cfg, deps)
}

func startDriverWithDependencies(t *testing.T, ctx context.Context, cfg tor.Config, deps tor.Dependencies) *tor.Driver {
	t.Helper()
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

type testCloserFunc func() error

func (f testCloserFunc) Close() error { return f() }

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

type wrongProxyPasswordFS struct{ tor.FileSystem }

func (f *wrongProxyPasswordFS) WriteFile(path string, data []byte, mode fs.FileMode, owner *tor.Identity) error {
	if filepath.Base(path) == "torrc" {
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "Socks5ProxyPassword ") {
				lines[i] = "Socks5ProxyPassword deliberately-wrong"
			}
		}
		data = []byte(strings.Join(lines, "\n"))
	}
	return f.FileSystem.WriteFile(path, data, mode, owner)
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
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = service.Listen(ctx, "tcp", ":80")
	if err != nil {
		t.Fatal(err)
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

func TestTorOfflineTypedClientOptionsAndRuntimeBridges(t *testing.T) {
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fingerprint := tor.Fingerprint(strings.Repeat("1", 40))
	cfg := torConfig(t)
	cfg.ConnectionPadding = tor.ReducedConnectionPadding
	cfg.CircuitPadding = tor.ReducedCircuitPadding
	cfg.ReachableORPorts = []uint16{443}
	cfg.MaxPendingCircuits = 4
	cfg.NumCPUs = 1
	cfg.ClientIP = tor.ClientPreferIPv6
	cfg.OnionTraffic = tor.RejectOnionTraffic
	cfg.ExcludeExitNodes = []tor.Fingerprint{fingerprint}
	d := startDriver(t, ctx, cfg, nil)
	if err := d.SetBridges(ctx, tor.BridgeConfig{
		UseBridges: true,
		Bridges:    []tor.Bridge{{Address: "192.0.2.1:443", Fingerprint: fingerprint}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetBridges(ctx, tor.BridgeConfig{}); err != nil {
		t.Fatal(err)
	}
}

type offlineOnionKeys struct {
	mu   sync.Mutex
	keys map[string]tor.OnionServiceKey
}

func (s *offlineOnionKeys) Load(_ context.Context, name string) (tor.OnionServiceKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[name]
	if !ok {
		return tor.OnionServiceKey{}, fs.ErrNotExist
	}
	return key, nil
}

func (s *offlineOnionKeys) Store(_ context.Context, name string, key tor.OnionServiceKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = make(map[string]tor.OnionServiceKey)
	}
	if _, exists := s.keys[name]; exists {
		return fs.ErrExist
	}
	s.keys[name] = key
	return nil
}

func TestTorOfflinePersistentServiceIdentity(t *testing.T) {
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store := &offlineOnionKeys{}
	var address string
	for restart := 0; restart < 2; restart++ {
		deps := direct.Dependencies(direct.Network(), nil, testLogger{t: t})
		deps.OnionKeys = store
		d := startDriverWithDependencies(t, ctx, torConfig(t), deps)
		service, err := d.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80}, KeyName: "offline-test"})
		if err != nil {
			t.Fatal(err)
		}
		if restart == 0 {
			address = service.Address()
		} else if service.Address() != address {
			t.Fatalf("service address changed after restart: %s != %s", service.Address(), address)
		}
		if err = service.Close(); err != nil {
			t.Fatal(err)
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
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

	for generation := 0; generation < 3; generation++ {
		replacement := &countedNetwork{Network: direct.Network()}
		if err = d.SetOutbound(replacement); err != nil {
			t.Fatal(err)
		}
		if err = d.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		retryHTTP(t, ctx, n, url, "private Tor e2e")
		if replacement.attempts.Load() == 0 {
			t.Fatalf("Tor did not use outbound generation %d", generation+1)
		}
		if generation < 2 {
			if err = d.SetOutbound(nil); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTorPrivateProtectedOnionPublication(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	server := startDriver(t, ctx, torConfig(t), direct.Network())
	if err := server.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	authorization, err := server.GenerateClientAuthorization("private_test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := authorization.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	service, err := server.NewService(ctx, tor.ServiceConfig{
		Ports: []uint16{80}, AuthorizedClients: []tor.ClientAuthorizationPublicKey{public},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	if err = service.WaitPublished(ctx); err != nil {
		t.Fatal(err)
	}
	if err = server.AddClientAuthorization(ctx, service.Address(), authorization); err != nil {
		t.Fatal(err)
	}
	if err = server.RemoveClientAuthorization(ctx, service.Address()); err != nil {
		t.Fatal(err)
	}
}

func TestTorPrivateCircuitIsolation(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	hold, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, acceptErr := hold.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- conn
		}
	}()

	d := startDriver(t, ctx, torConfig(t), direct.Network())
	if err = d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	sessionA, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.SessionCircuits})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessionA.Close() }()
	sessionB, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.SessionCircuits})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessionB.Close() }()
	perConnection, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.IsolateEachConnection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = perConnection.Close() }()

	var clients []net.Conn
	var servers []net.Conn
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
		for _, conn := range servers {
			_ = conn.Close()
		}
	}()
	for _, network := range []*tor.Network{sessionA, sessionA, sessionB, perConnection, perConnection} {
		conn, dialErr := network.Dial(ctx, "tcp4", hold.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clients = append(clients, conn)
		select {
		case conn = <-accepted:
			servers = append(servers, conn)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}

	tokenA := sessionA.TestIsolationToken()
	tokenB := sessionB.TestIsolationToken()
	deadline := time.Now().Add(20 * time.Second)
	for {
		circuits, statusErr := d.TestIsolationCircuits(ctx)
		if statusErr != nil {
			t.Fatal(statusErr)
		}
		byToken := make(map[string]map[string]struct{})
		for _, circuit := range circuits {
			if byToken[circuit.Password] == nil {
				byToken[circuit.Password] = make(map[string]struct{})
			}
			byToken[circuit.Password][circuit.ID] = struct{}{}
		}
		isolated := 0
		ownerByCircuit := make(map[string]string)
		collision := false
		for token, ids := range byToken {
			if token != tokenA && token != tokenB && len(token) == 64 {
				isolated++
			}
			for id := range ids {
				if owner, exists := ownerByCircuit[id]; exists && owner != token {
					collision = true
				}
				ownerByCircuit[id] = token
			}
		}
		_, aOK := byToken[tokenA]
		_, bOK := byToken[tokenB]
		if aOK && bOK && isolated >= 2 && !collision {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("circuit isolation evidence incomplete: %#v", byToken)
		}
		time.Sleep(100 * time.Millisecond)
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
	url := localHTTPServer(t)
	retryHTTP(t, ctx, n, url, "private Tor e2e")
	if out.attempts.Load() == 0 || out.unexpected.Load() {
		t.Fatal("obfs4 did not exclusively request the private bridge through the injected proxy")
	}
	if err = d.SetOutbound(nil); err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 3*time.Second)
	if conn, dialErr := n.Dial(blocked, "tcp", strings.TrimPrefix(url, "http://")); dialErr == nil {
		_ = conn.Close()
		stop()
		t.Fatal("obfs4 traffic survived outbound removal")
	}
	stop()
	replacement := &countedNetwork{Network: direct.Network(), allowed: bridgeAddress}
	if err = d.SetOutbound(replacement); err != nil {
		t.Fatal(err)
	}
	if err = d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	retryHTTP(t, ctx, n, url, "private Tor e2e")
	if replacement.attempts.Load() == 0 || replacement.unexpected.Load() {
		t.Fatal("obfs4 did not recover through the replacement outbound network")
	}
}

func TestTorPrivateRuntimeBridgeReplacement(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	bridgeCfg, bridgeAddress := obfs4Config(t, torConfig(t))
	directCfg := torConfig(t)
	directCfg.Transports = bridgeCfg.Transports
	d := startDriver(t, ctx, directCfg, direct.Network())
	events, cancelEvents, err := d.SubscribeEvents(256)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEvents()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.SetOutbound(nil); err != nil {
		t.Fatal(err)
	}
	bridgeRuntimeCfg := tor.BridgeConfig{
		UseBridges: true,
		Bridges:    bridgeCfg.Bridges,
		Transports: bridgeCfg.Transports,
	}
	for replacement := 0; replacement < 6; replacement++ {
		if err := d.SetBridges(ctx, bridgeRuntimeCfg); err != nil {
			t.Fatalf("enable runtime bridge replacement %d: %v", replacement, err)
		}
		if replacement < 5 {
			if err := d.SetBridges(ctx, tor.BridgeConfig{}); err != nil {
				t.Fatalf("disable runtime bridge replacement %d: %v", replacement, err)
			}
		}
	}
	restricted := &countedNetwork{Network: direct.Network(), allowed: bridgeAddress}
	if err := d.SetOutbound(restricted); err != nil {
		t.Fatal(err)
	}
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.IsolateEachConnection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	retryHTTP(t, ctx, n, localHTTPServer(t), "private Tor e2e")
	if restricted.attempts.Load() == 0 || restricted.unexpected.Load() {
		t.Fatal("runtime bridge mode did not exclusively use the configured bridge")
	}
	eventDeadline := time.NewTimer(10 * time.Second)
	defer eventDeadline.Stop()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("driver event subscription closed during runtime bridge replacement")
			}
			transport, ok := event.(tor.TransportEvent)
			if !ok {
				continue
			}
			if transport.Transport != tor.Obfs4 {
				t.Fatalf("runtime replacement reported inconsistent transport: %#v", transport)
			}
			return
		case <-eventDeadline.C:
			t.Fatal("runtime bridge replacement produced no typed transport event")
		}
	}
}

func TestTorPrivateDriverCloseFinalizesPersistentServices(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store := &offlineOnionKeys{}
	var address string

	for restart := 0; restart < 2; restart++ {
		deps := direct.Dependencies(direct.Network(), nil, testLogger{t: t})
		extra, err := os.ReadFile(os.Getenv("TOR_DRIVER_TEST_TORRC_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		deps.FS = &testTorrcFS{FileSystem: deps.FS, extra: extra}
		deps.OnionKeys = store
		d := startDriverWithDependencies(t, ctx, torConfig(t), deps)
		service, err := d.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80}, KeyName: "driver-close"})
		if err != nil {
			t.Fatal(err)
		}
		listener, err := service.Listen(ctx, "tcp", ":80")
		if err != nil {
			t.Fatal(err)
		}
		closed := make(chan struct{})
		if _, err = service.SubscribeCloser(testCloserFunc(func() error { close(closed); return nil })); err != nil {
			t.Fatal(err)
		}
		if restart == 0 {
			address = service.Address()
		} else if service.Address() != address {
			t.Fatalf("service address changed after driver-owned close: %s != %s", service.Address(), address)
		}

		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Driver.Close did not notify the service close subscriber")
		}
		if _, err = listener.Accept(); err == nil {
			t.Fatal("service listener survived Driver.Close")
		}
		waitCtx, stop := context.WithTimeout(ctx, time.Second)
		if err = service.WaitPublished(waitCtx); !errors.Is(err, tor.ErrClosed) {
			stop()
			t.Fatalf("WaitPublished() after Driver.Close = %v, want ErrClosed", err)
		}
		stop()
		if err = service.Close(); err != nil {
			t.Fatalf("Service.Close() after Driver.Close: %v", err)
		}
	}
}

func TestTorPrivateObfs4ProxyFailureRecovery(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg, bridgeAddress := obfs4Config(t, torConfig(t))
	failing := &countedNetwork{Network: &gonnect.RejectNetwork{}, allowed: bridgeAddress}
	d := startDriver(t, ctx, cfg, failing)
	deadline := time.Now().Add(20 * time.Second)
	for failing.attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if failing.attempts.Load() == 0 {
		t.Fatal("transport did not reach the failing injected proxy backend")
	}
	replacement := &countedNetwork{Network: direct.Network(), allowed: bridgeAddress}
	if err := d.SetOutbound(replacement); err != nil {
		t.Fatal(err)
	}
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if replacement.attempts.Load() == 0 || replacement.unexpected.Load() {
		t.Fatal("transport did not recover exclusively through the replacement")
	}
}

func TestTorPrivateObfs4WrongProxyCredentials(t *testing.T) {
	privateFixture(t)
	trackGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, bridgeAddress := obfs4Config(t, torConfig(t))
	out := &countedNetwork{Network: direct.Network(), allowed: bridgeAddress}
	deps := direct.Dependencies(direct.Network(), out, testLogger{t: t})
	extra, err := os.ReadFile(os.Getenv("TOR_DRIVER_TEST_TORRC_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	deps.FS = &wrongProxyPasswordFS{FileSystem: &testTorrcFS{FileSystem: deps.FS, extra: extra}}
	d := startDriverWithDependencies(t, ctx, cfg, deps)
	ready, stop := context.WithTimeout(ctx, 5*time.Second)
	err = d.WaitReady(ready)
	stop()
	if err == nil {
		t.Fatal("obfs4 bootstrapped with wrong upstream proxy credentials")
	}
	if out.attempts.Load() != 0 {
		t.Fatal("wrong credentials reached the outbound backend")
	}
}

func TestTorPrivateTransportFailures(t *testing.T) {
	privateFixture(t)
	for _, tc := range []struct {
		name string
		env  string
	}{
		{name: "crash", env: "TOR_PT_FIXTURE_CRASH"},
		{name: "missing_proxy_support", env: "TOR_PT_FIXTURE_NO_PROXY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary := os.Getenv(tc.env)
			if binary == "" {
				t.Fatal("private fixture did not provide " + tc.env)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cfg, _ := obfs4Config(t, torConfig(t))
			cfg.Transports[0].Executable = binary
			cfg.StateDirectory = t.TempDir()
			out := &countedNetwork{Network: direct.Network()}
			d := startDriver(t, ctx, cfg, out)
			report := waitTransportReport(t, cfg.StateDirectory, filepath.Base(binary))
			if !strings.Contains(report, "proxy_present=true") || !strings.Contains(report, "proxy_authenticated=true") {
				t.Fatalf("Tor did not supply an authenticated TOR_PT_PROXY: %q", report)
			}
			ready, stop := context.WithTimeout(ctx, 3*time.Second)
			err := d.WaitReady(ready)
			stop()
			if err == nil {
				t.Fatal("Tor bootstrapped with a failed transport")
			}
			if out.attempts.Load() != 0 {
				t.Fatal("failed transport reached the outbound backend")
			}
		})
	}
}

func TestTorPrivateTransportExternalSocketDenial(t *testing.T) {
	privateFixture(t)
	binary := os.Getenv("TOR_PT_FIXTURE_ESCAPE")
	if binary == "" {
		t.Fatal("private fixture did not provide TOR_PT_FIXTURE_ESCAPE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, _ := obfs4Config(t, torConfig(t))
	cfg.Transports[0].Executable = binary
	cfg.StateDirectory = t.TempDir()
	startDriver(t, ctx, cfg, direct.Network())
	report := waitTransportReport(t, cfg.StateDirectory, filepath.Base(binary))
	for _, evidence := range []string{
		"proxy_present=true", "proxy_authenticated=true", "ipv4_denied=true",
		"ipv6_denied=true", "dns_attempted=true", "dns_denied=true",
	} {
		if !strings.Contains(report, evidence) {
			t.Fatalf("transport escape report lacks %q: %q", evidence, report)
		}
	}
}

func waitTransportReport(t *testing.T, state, mode string) string {
	t.Helper()
	path := filepath.Join(state, "pt_state", mode+".report")
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return string(data)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("transport report was not written: %s", path)
	return ""
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
	if err = s.WaitPublished(ctx); err != nil {
		t.Fatal(err)
	}
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
