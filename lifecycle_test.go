package tordriver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

var errFixture = errors.New("fixture failure")

type fixtureClock struct{}

type fixtureErrorReader struct{}

func (fixtureErrorReader) Read([]byte) (int, error) { return 0, errFixture }

func (fixtureClock) Now() time.Time { return time.Now() }
func (fixtureClock) Timeout(ctx context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 100*time.Millisecond)
}
func (fixtureClock) Sleep(ctx context.Context, _ time.Duration) error {
	t := time.NewTimer(time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type fixtureFS struct {
	mu        sync.Mutex
	root      string
	stage     string
	files     map[string][]byte
	removed   bool
	removeErr error
}

func (f *fixtureFS) TempDir(string, string) (string, error) {
	if f.stage == "temporary directory" {
		return "", errFixture
	}
	return f.root, nil
}
func (f *fixtureFS) PrivateDir(path string, _ *Identity) error {
	if (f.stage == "work directory" && path == f.root) || (f.stage == "state directory" && path != f.root) {
		return errFixture
	}
	return nil
}
func (f *fixtureFS) WriteFile(path string, data []byte, _ fs.FileMode, _ *Identity) error {
	base := filepath.Base(path)
	if (f.stage == "defaults file" && base == "defaults-torrc") || (f.stage == "configuration file" && base == "torrc") {
		return errFixture
	}
	f.mu.Lock()
	f.files[path] = append([]byte(nil), data...)
	f.mu.Unlock()
	return nil
}
func (f *fixtureFS) ReadFile(path string, limit int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if int64(len(b)) > limit {
		return nil, errFixture
	}
	return append([]byte(nil), b...), nil
}
func (f *fixtureFS) RemoveAll(path string) error {
	if path != f.root {
		return fmt.Errorf("unexpected removal target %q", path)
	}
	f.mu.Lock()
	if f.removeErr != nil {
		err := f.removeErr
		f.mu.Unlock()
		return err
	}
	f.removed = true
	f.files = make(map[string][]byte)
	f.mu.Unlock()
	return nil
}
func (f *fixtureFS) put(path string, data []byte) {
	f.mu.Lock()
	f.files[path] = append([]byte(nil), data...)
	f.mu.Unlock()
}
func (f *fixtureFS) text(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.files[path])
}
func (f *fixtureFS) wasRemoved() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.removed
}

type fixtureProcess struct {
	mu         sync.Mutex
	done       chan struct{}
	once       sync.Once
	waitErr    error
	waited     bool
	killed     bool
	released   bool
	releaseErr error
	listener   net.Listener
	conn       net.Conn
	ignoreStop bool
}

func (p *fixtureProcess) Wait() error {
	<-p.done
	p.mu.Lock()
	p.waited = true
	err := p.waitErr
	p.mu.Unlock()
	return err
}
func (p *fixtureProcess) Kill() error {
	p.mu.Lock()
	p.killed = true
	p.mu.Unlock()
	p.finish(errors.New("fixture process killed"))
	return nil
}
func (p *fixtureProcess) Release() error {
	p.mu.Lock()
	p.released = true
	p.mu.Unlock()
	return p.releaseErr
}
func (p *fixtureProcess) finish(err error) {
	p.once.Do(func() {
		p.mu.Lock()
		p.waitErr = err
		listener := p.listener
		conn := p.conn
		p.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		close(p.done)
	})
}
func (p *fixtureProcess) snapshot() (waited, killed, released bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waited, p.killed, p.released
}

type fixtureProcesses struct {
	fs                   *fixtureFS
	stage                string
	mu                   sync.Mutex
	servers              sync.WaitGroup
	proc                 *fixtureProcess
	commands             []string
	addCount             int
	rejectAddAt          int
	rejectBridge         bool
	rejectBridgeRollback bool
	rejectDisable        bool
	rejectEnable         bool
	socksEndpoint        string
}

func (p *fixtureProcesses) PID() int         { return 1234 }
func (p *fixtureProcesses) Platform() string { return "linux" }
func (p *fixtureProcesses) Start(_ context.Context, launch Launch) (Process, error) {
	if p.stage == "spawn" {
		return nil, errFixture
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proc := &fixtureProcess{done: make(chan struct{}), listener: l, ignoreStop: p.stage == "shutdown timeout"}
	p.mu.Lock()
	p.proc = proc
	p.mu.Unlock()
	if p.stage == "child crash during startup" {
		proc.finish(errFixture)
		return proc, nil
	}

	port := "PORT=" + l.Addr().String() + "\n"
	switch p.stage {
	case "malformed port":
		port = "not-a-port\n"
	case "partial port":
		port = "PORT=127.0.0.1:\n"
	}
	p.fs.put(filepath.Join(launch.Directory, "control-port"), []byte(port))
	cookie := bytes.Repeat([]byte{0x42}, 32)
	switch p.stage {
	case "malformed cookie":
		cookie = bytes.Repeat([]byte{0x42}, 33)
	case "partial cookie":
		cookie = cookie[:16]
	}
	p.fs.put(filepath.Join(launch.Directory, "control-cookie"), cookie)
	proxy := ""
	for _, line := range strings.Split(p.fs.text(filepath.Join(launch.Directory, "torrc")), "\n") {
		if value, ok := strings.CutPrefix(line, "Socks5Proxy "); ok {
			proxy = value
		}
	}
	p.servers.Add(1)
	go func() {
		defer p.servers.Done()
		p.serveControl(proc, cookie, proxy)
	}()
	return proc, nil
}
func (p *fixtureProcesses) serveControl(proc *fixtureProcess, cookie []byte, proxy string) {
	conn, err := proc.listener.Accept()
	if err != nil {
		return
	}
	proc.mu.Lock()
	proc.conn = conn
	proc.mu.Unlock()
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		p.mu.Lock()
		p.commands = append(p.commands, line)
		p.mu.Unlock()
		switch {
		case line == "PROTOCOLINFO 1":
			methods := "SAFECOOKIE"
			if p.stage == "missing SAFECOOKIE" {
				methods = "COOKIE"
			}
			_, _ = fmt.Fprintf(conn, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=%s\r\n250 OK\r\n", methods)
		case strings.HasPrefix(line, "AUTHCHALLENGE SAFECOOKIE "):
			client, decodeErr := hex.DecodeString(strings.TrimPrefix(line, "AUTHCHALLENGE SAFECOOKIE "))
			if decodeErr != nil {
				_, _ = io.WriteString(conn, "513 BAD\r\n")
				continue
			}
			server := bytes.Repeat([]byte{0x24}, 32)
			h := hmac.New(sha256.New, []byte("Tor safe cookie authentication server-to-controller hash"))
			_, _ = h.Write(cookie)
			_, _ = h.Write(client)
			_, _ = h.Write(server)
			hash := h.Sum(nil)
			if p.stage == "invalid SAFECOOKIE proof" {
				hash[0] ^= 1
			}
			_, _ = fmt.Fprintf(conn, "250 AUTHCHALLENGE SERVERHASH=%x SERVERNONCE=%x\r\n", hash, server)
		case strings.HasPrefix(line, "AUTHENTICATE "):
			if p.stage == "authentication rejection" {
				_, _ = io.WriteString(conn, "515 AUTHENTICATION_FAILED\r\n")
			} else {
				_, _ = io.WriteString(conn, "250 OK\r\n")
			}
		case line == "TAKEOWNERSHIP" && p.stage == "lost control during startup":
			return
		case line == "TAKEOWNERSHIP" && p.stage == "ownership rejection":
			_, _ = io.WriteString(conn, "551 OWNERSHIP_FAILED\r\n")
		case line == "RESETCONF __OwningControllerProcess" && p.stage == "ownership reset rejection":
			_, _ = io.WriteString(conn, "551 RESET_FAILED\r\n")
		case line == "USEFEATURE EXTENDED_EVENTS VERBOSE_NAMES", strings.HasPrefix(line, "SETEVENTS "):
			_, _ = io.WriteString(conn, "250 OK\r\n")
		case line == "GETINFO events/names":
			_, _ = io.WriteString(conn, "250-events/names=STATUS_CLIENT HS_DESC TRANSPORT_LAUNCHED PT_LOG PT_STATUS\r\n250 OK\r\n")
		case line == "GETINFO status/bootstrap-phase":
			_, _ = io.WriteString(conn, "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=0 TAG=starting SUMMARY=\"Starting\"\r\n250 OK\r\n")
		case line == "SETCONF DisableNetwork=0" && p.stage == "enable network rejection":
			_, _ = io.WriteString(conn, "551 SETCONF_FAILED\r\n")
		case strings.HasPrefix(line, "SETCONF UseBridges="):
			p.mu.Lock()
			reject := p.rejectBridge || (p.rejectBridgeRollback && strings.HasPrefix(line, "SETCONF UseBridges=0"))
			p.rejectBridge = false
			if reject && strings.HasPrefix(line, "SETCONF UseBridges=0") {
				p.rejectBridgeRollback = false
			}
			p.mu.Unlock()
			if reject {
				_, _ = io.WriteString(conn, "553 BRIDGE_CONFIG_REJECTED\r\n")
			} else {
				_, _ = io.WriteString(conn, "250 OK\r\n")
			}
		case line == "SETCONF DisableNetwork=0":
			p.mu.Lock()
			reject := p.rejectEnable
			p.rejectEnable = false
			p.mu.Unlock()
			if reject {
				_, _ = io.WriteString(conn, "553 NETWORK_ENABLE_REJECTED\r\n")
			} else {
				_, _ = io.WriteString(conn, "250 OK\r\n")
			}
		case line == "SETCONF DisableNetwork=1":
			p.mu.Lock()
			reject := p.rejectDisable
			p.rejectDisable = false
			p.mu.Unlock()
			if reject {
				_, _ = io.WriteString(conn, "553 NETWORK_DISABLE_REJECTED\r\n")
			} else {
				_, _ = io.WriteString(conn, "250 OK\r\n")
			}
		case line == "TAKEOWNERSHIP", line == "RESETCONF __OwningControllerProcess":
			_, _ = io.WriteString(conn, "250 OK\r\n")
		case line == "GETCONF Socks5Proxy":
			switch p.stage {
			case "proxy query rejection":
				_, _ = io.WriteString(conn, "551 GETCONF_FAILED\r\n")
			case "proxy mismatch":
				_, _ = io.WriteString(conn, "250-Socks5Proxy=127.0.0.1:1\r\n250 OK\r\n")
			default:
				_, _ = fmt.Fprintf(conn, "250-Socks5Proxy=%s\r\n250 OK\r\n", proxy)
			}
		case line == "GETINFO net/listeners/socks":
			switch p.stage {
			case "SOCKS query rejection":
				_, _ = io.WriteString(conn, "551 GETINFO_FAILED\r\n")
			case "malformed SOCKS listener":
				_, _ = io.WriteString(conn, "250-net/listeners/socks=\"not-an-endpoint\"\r\n250 OK\r\n")
			case "missing SOCKS listener":
				_, _ = io.WriteString(conn, "250 OK\r\n")
			default:
				p.mu.Lock()
				endpoint := p.socksEndpoint
				p.mu.Unlock()
				if endpoint == "" {
					endpoint = "127.0.0.1:19050"
				}
				_, _ = fmt.Fprintf(conn, "250-net/listeners/socks=\"%s\"\r\n250 OK\r\n", endpoint)
			}
		case strings.HasPrefix(line, "ADD_ONION "):
			p.mu.Lock()
			p.addCount++
			reject := p.rejectAddAt == p.addCount
			p.mu.Unlock()
			if reject {
				_, _ = io.WriteString(conn, "551 ADD_FAILED\r\n")
				continue
			}
			if strings.HasPrefix(line, "ADD_ONION NEW:ED25519-V3") {
				key := make([]byte, 64)
				key[31] = 64
				_, _ = fmt.Fprintf(conn, "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n250-PrivateKey=ED25519-V3:%s\r\n250 OK\r\n", base64.RawStdEncoding.EncodeToString(key))
			} else {
				_, _ = io.WriteString(conn, "250-ServiceID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n250 OK\r\n")
			}
		case strings.HasPrefix(line, "DEL_ONION "):
			_, _ = io.WriteString(conn, "250 OK\r\n")
		case strings.HasPrefix(line, "ONION_CLIENT_AUTH_ADD "), strings.HasPrefix(line, "ONION_CLIENT_AUTH_REMOVE "):
			_, _ = io.WriteString(conn, "250 OK\r\n")
		case line == "SIGNAL SHUTDOWN":
			if proc.ignoreStop {
				continue
			}
			_, _ = io.WriteString(conn, "250 OK\r\n")
			proc.finish(nil)
			return
		default:
			_, _ = io.WriteString(conn, "510 UNRECOGNIZED\r\n")
		}
	}
}
func (p *fixtureProcesses) process() *fixtureProcess {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proc
}
func (p *fixtureProcesses) commandLines() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.commands...)
}
func (p *fixtureProcesses) rejectNextAdd() {
	p.mu.Lock()
	p.rejectAddAt = p.addCount + 1
	p.mu.Unlock()
}
func (p *fixtureProcesses) rejectNextBridgeChange() {
	p.mu.Lock()
	p.rejectBridge = true
	p.mu.Unlock()
}
func (p *fixtureProcesses) rejectNextBridgeRollback() {
	p.mu.Lock()
	p.rejectBridgeRollback = true
	p.mu.Unlock()
}
func (p *fixtureProcesses) rejectNextNetworkDisable() {
	p.mu.Lock()
	p.rejectDisable = true
	p.mu.Unlock()
}
func (p *fixtureProcesses) rejectNextNetworkEnable() {
	p.mu.Lock()
	p.rejectEnable = true
	p.mu.Unlock()
}
func (p *fixtureProcesses) setSocksEndpoint(endpoint string) {
	p.mu.Lock()
	p.socksEndpoint = endpoint
	p.mu.Unlock()
}
func (p *fixtureProcesses) sendEvent(t *testing.T, event string) {
	t.Helper()
	proc := p.process()
	proc.mu.Lock()
	conn := proc.conn
	proc.mu.Unlock()
	if conn == nil {
		t.Fatal("control connection is not ready")
	}
	if _, err := io.WriteString(conn, "650 "+event+"\r\n"); err != nil {
		t.Fatal(err)
	}
}
func (p *fixtureProcesses) waitForServers(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		p.servers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture process goroutine did not stop")
	}
}

type trackedNetwork struct {
	gonnect.Network
	mu            sync.Mutex
	active        int
	listenErr     error
	dialErr       error
	listenerClose error
}

func (n *trackedNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if n.dialErr != nil {
		return nil, n.dialErr
	}
	c, err := n.Network.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.active++
	n.mu.Unlock()
	return &trackedConn{Conn: c, close: n.closed}, nil
}
func (n *trackedNetwork) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if n.listenErr != nil {
		return nil, n.listenErr
	}
	l, err := n.Network.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.active++
	n.mu.Unlock()
	return &trackedListener{Listener: l, network: n}, nil
}
func (n *trackedNetwork) closed() {
	n.mu.Lock()
	n.active--
	n.mu.Unlock()
}
func (n *trackedNetwork) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.active
}

type trackedConn struct {
	net.Conn
	once  sync.Once
	close func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.close)
	return err
}

type trackedListener struct {
	net.Listener
	network *trackedNetwork
	once    sync.Once
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.network.mu.Lock()
	l.network.active++
	l.network.mu.Unlock()
	return &trackedConn{Conn: c, close: l.network.closed}, nil
}
func (l *trackedListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() {
		l.network.closed()
	})
	return errors.Join(err, l.network.listenerClose)
}

type lifecycleFixture struct {
	fs        *fixtureFS
	processes *fixtureProcesses
	local     *trackedNetwork
	deps      Dependencies
	cfg       Config
}

func newLifecycleFixture(t *testing.T, stage string) *lifecycleFixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "virtual-work")
	f := &fixtureFS{root: root, stage: stage, files: make(map[string][]byte)}
	p := &fixtureProcesses{fs: f, stage: stage}
	local := &trackedNetwork{Network: gonnect.NativeConfig{}.Build()}
	if stage == "listener" {
		local.listenErr = errFixture
	}
	if stage == "control dial" {
		local.dialErr = errFixture
	}
	random := io.Reader(bytes.NewReader(make([]byte, 4096)))
	if stage == "entropy" {
		random = fixtureErrorReader{}
	}
	return &lifecycleFixture{
		fs:        f,
		processes: p,
		local:     local,
		deps: Dependencies{
			FS: f, Processes: p, Clock: fixtureClock{},
			Random: random, Logger: NopLogger{}, LocalNetwork: local,
		},
		cfg: Config{TorExecutable: filepath.Join(base, "tor"), StartupTimeout: time.Second, CommandTimeout: time.Second, DialTimeout: time.Second, ShutdownTimeout: time.Second},
	}
}

func TestInjectedStartupRollback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		stage      string
		starts     bool
		wantNeedle string
	}{
		{name: "temporary_directory", stage: "temporary directory", wantNeedle: "fixture failure"},
		{name: "work_directory", stage: "work directory", wantNeedle: "fixture failure"},
		{name: "state_directory", stage: "state directory", wantNeedle: "fixture failure"},
		{name: "defaults_file", stage: "defaults file", wantNeedle: "fixture failure"},
		{name: "configuration_file", stage: "configuration file", wantNeedle: "fixture failure"},
		{name: "entropy", stage: "entropy", wantNeedle: "fixture failure"},
		{name: "listener", stage: "listener", wantNeedle: "fixture failure"},
		{name: "spawn", stage: "spawn", wantNeedle: "fixture failure"},
		{name: "malformed_port", stage: "malformed port", starts: true, wantNeedle: "invalid control endpoint"},
		{name: "partial_port", stage: "partial port", starts: true, wantNeedle: "invalid control endpoint"},
		{name: "control_dial", stage: "control dial", starts: true, wantNeedle: "fixture failure"},
		{name: "malformed_cookie", stage: "malformed cookie", starts: true, wantNeedle: "fixture failure"},
		{name: "partial_cookie", stage: "partial cookie", starts: true, wantNeedle: "cookie must contain 32 bytes"},
		{name: "missing_SAFECOOKIE", stage: "missing SAFECOOKIE", starts: true, wantNeedle: "SAFECOOKIE required"},
		{name: "invalid_SAFECOOKIE_proof", stage: "invalid SAFECOOKIE proof", starts: true, wantNeedle: "server proof failed"},
		{name: "authentication_rejection", stage: "authentication rejection", starts: true, wantNeedle: "status 515"},
		{name: "lost_control", stage: "lost control during startup", starts: true, wantNeedle: "EOF"},
		{name: "ownership_rejection", stage: "ownership rejection", starts: true, wantNeedle: "status 551"},
		{name: "ownership_reset_rejection", stage: "ownership reset rejection", starts: true, wantNeedle: "status 551"},
		{name: "proxy_query_rejection", stage: "proxy query rejection", starts: true, wantNeedle: "status 551"},
		{name: "proxy_mismatch", stage: "proxy mismatch", starts: true, wantNeedle: "mandatory upstream proxy"},
		{name: "enable_network_rejection", stage: "enable network rejection", starts: true, wantNeedle: "status 551"},
		{name: "SOCKS_query_rejection", stage: "SOCKS query rejection", starts: true, wantNeedle: "status 551"},
		{name: "malformed_SOCKS_listener", stage: "malformed SOCKS listener", starts: true, wantNeedle: "invalid numeric endpoint"},
		{name: "missing_SOCKS_listener", stage: "missing SOCKS listener", starts: true, wantNeedle: "did not report a SOCKS listener"},
		{name: "child_crash", stage: "child crash during startup", starts: true, wantNeedle: "fixture failure"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newLifecycleFixture(t, tc.stage)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			d, err := Start(ctx, f.cfg, f.deps)
			if d != nil || err == nil || !strings.Contains(err.Error(), tc.wantNeedle) {
				t.Fatalf("Start() = (%v, %v), want error containing %q", d, err, tc.wantNeedle)
			}
			proc := f.processes.process()
			if tc.starts {
				if proc == nil {
					t.Fatal("process was not started")
				}
				waited, _, released := proc.snapshot()
				if !waited || !released {
					t.Fatalf("process cleanup: waited=%v released=%v", waited, released)
				}
			} else if proc != nil {
				t.Fatal("process started before the injected failure")
			}
			if tc.stage != "temporary directory" && !f.fs.wasRemoved() {
				t.Fatal("temporary files were not removed")
			}
			if active := f.local.count(); active != 0 {
				t.Fatalf("%d local sockets remain active", active)
			}
			f.processes.waitForServers(t)
		})
	}
}

func TestInjectedLifecycleAndCleanupFailures(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		waited, killed, released := f.processes.process().snapshot()
		if !waited || killed || !released || !f.fs.wasRemoved() || f.local.count() != 0 {
			t.Fatalf("incomplete cleanup: waited=%v killed=%v released=%v removed=%v sockets=%d", waited, killed, released, f.fs.wasRemoved(), f.local.count())
		}
		f.processes.waitForServers(t)
	})
	t.Run("shutdown_timeout", func(t *testing.T) {
		f := newLifecycleFixture(t, "shutdown timeout")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		err = d.Close()
		if err == nil || !strings.Contains(err.Error(), "graceful shutdown timed out") {
			t.Fatalf("Close() error = %v", err)
		}
		waited, killed, released := f.processes.process().snapshot()
		if !waited || !killed || !released || !f.fs.wasRemoved() || f.local.count() != 0 {
			t.Fatalf("forced cleanup incomplete: waited=%v killed=%v released=%v removed=%v sockets=%d", waited, killed, released, f.fs.wasRemoved(), f.local.count())
		}
		f.processes.waitForServers(t)
	})
	for _, tc := range []struct {
		name string
		set  func(*lifecycleFixture)
	}{
		{name: "filesystem", set: func(f *lifecycleFixture) { f.fs.removeErr = errFixture }},
		{name: "process_release", set: func(f *lifecycleFixture) {
			// Start installs the process. The error is set after startup below.
		}},
		{name: "listener", set: func(f *lifecycleFixture) { f.local.listenerClose = errFixture }},
	} {
		t.Run("cleanup_"+tc.name, func(t *testing.T) {
			f := newLifecycleFixture(t, "")
			tc.set(f)
			d, err := Start(context.Background(), f.cfg, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "process_release" {
				f.processes.process().releaseErr = errFixture
			}
			if err = d.Close(); !errors.Is(err, errFixture) {
				t.Fatalf("Close() error = %v, want fixture failure", err)
			}
			f.processes.waitForServers(t)
		})
	}
}

func TestRuntimeBridgeChangeIsTransactionalAndFailClosed(t *testing.T) {
	bridge := Bridge{Address: "192.0.2.1:443"}

	t.Run("unapproved_transport", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.processes.commandLines())
		err = d.SetBridges(context.Background(), BridgeConfig{
			Transports: []TransportConfig{{Kind: Obfs4, Executable: absoluteBinary(t)}},
		})
		if err == nil || !strings.Contains(err.Error(), "not approved") {
			t.Fatalf("SetBridges() error = %v", err)
		}
		if got := len(f.processes.commandLines()); got != before {
			t.Fatal("unapproved transport reached the controller")
		}
		_ = d.Close()
		f.processes.waitForServers(t)
	})

	t.Run("success", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		logger := &eventTestLogger{}
		f.cfg.ForwardTorLogs = true
		f.deps.Logger = logger
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		f.processes.setSocksEndpoint("127.0.0.1:19051")
		if err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{bridge}}); err != nil {
			t.Fatal(err)
		}
		if got := d.socksEndpoint(); got != "127.0.0.1:19051" {
			t.Fatalf("SOCKS endpoint = %q, want refreshed listener", got)
		}
		commands := strings.Join(f.processes.commandLines(), "\n")
		want := "SETCONF DisableNetwork=1\nSETCONF UseBridges=1 ClientTransportPlugin Bridge=\"192.0.2.1:443\"\nSETCONF DisableNetwork=0"
		if !strings.Contains(commands, want) {
			t.Fatalf("bridge command sequence =\n%s", commands)
		}
		if _, err = d.logs.Write([]byte("runtime bridge " + bridge.Address + "\n")); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logger.String(), bridge.Address) {
			t.Fatalf("runtime bridge address reached forwarded logs: %q", logger.String())
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		f.processes.waitForServers(t)
	})

	t.Run("partial_log_across_replacement", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		logger := &eventTestLogger{}
		f.cfg.ForwardTorLogs = true
		f.deps.Logger = logger
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		first := Bridge{Address: "192.0.2.10:443"}
		second := Bridge{Address: "198.51.100.20:8443"}
		if err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{first}}); err != nil {
			t.Fatal(err)
		}
		if _, err = d.logs.Write([]byte("old runtime bridge " + first.Address)); err != nil {
			t.Fatal(err)
		}
		if err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{second}}); err != nil {
			t.Fatal(err)
		}
		if _, err = d.logs.Write([]byte(" new runtime bridge " + second.Address + "\n")); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{first.Address, second.Address} {
			if strings.Contains(logger.String(), secret) {
				t.Fatalf("runtime bridge address %q reached forwarded logs: %q", secret, logger.String())
			}
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		f.processes.waitForServers(t)
	})

	t.Run("delayed_complete_log_after_multiple_replacements", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		logger := &eventTestLogger{}
		f.cfg.ForwardTorLogs = true
		f.deps.Logger = logger
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		bridges := []Bridge{
			{Address: "192.0.2.30:443"},
			{Address: "198.51.100.40:8443"},
			{Address: "203.0.113.50:9443"},
		}
		for _, current := range bridges {
			if err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{current}}); err != nil {
				t.Fatal(err)
			}
		}
		for _, old := range bridges {
			if _, err = d.logs.Write([]byte("delayed runtime bridge " + old.Address + "\n")); err != nil {
				t.Fatal(err)
			}
		}
		for _, secret := range bridges {
			if strings.Contains(logger.String(), secret.Address) {
				t.Fatalf("delayed runtime bridge address %q reached forwarded logs: %q", secret.Address, logger.String())
			}
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		f.processes.waitForServers(t)
	})

	t.Run("delayed_log_for_rejected_configuration", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		logger := &eventTestLogger{}
		f.cfg.ForwardTorLogs = true
		f.deps.Logger = logger
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		rejected := Bridge{Address: "192.0.2.60:443"}
		accepted := Bridge{Address: "198.51.100.70:8443"}
		f.processes.rejectNextBridgeChange()
		if err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{rejected}}); err == nil {
			t.Fatal("rejected bridge configuration returned no error")
		}
		if err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{accepted}}); err != nil {
			t.Fatal(err)
		}
		if _, err = d.logs.Write([]byte("delayed rejected bridge " + rejected.Address + "\n")); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{rejected.Address, accepted.Address} {
			if strings.Contains(logger.String(), secret) {
				t.Fatalf("runtime bridge address %q reached forwarded logs: %q", secret, logger.String())
			}
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		f.processes.waitForServers(t)
	})

	t.Run("rejected_change_stays_disabled", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.processes.commandLines())
		f.processes.rejectNextBridgeChange()
		err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{bridge}})
		if err == nil || !strings.Contains(err.Error(), "networking remains disabled") {
			t.Fatalf("SetBridges() error = %v", err)
		}
		commands := f.processes.commandLines()[before:]
		if slices.Contains(commands, "SETCONF DisableNetwork=0") {
			t.Fatalf("failed bridge mode enabled direct guards: %q", commands)
		}
		_ = d.Close()
		f.processes.waitForServers(t)
	})

	t.Run("cannot_disable_direct_mode_closes_driver", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		f.processes.rejectNextNetworkDisable()
		err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{bridge}})
		if err == nil {
			t.Fatal("network disable failure was ignored")
		}
		select {
		case <-d.Done():
		default:
			t.Fatal("direct-mode driver remained active after network disable failed")
		}
		f.processes.waitForServers(t)
	})

	t.Run("enable_failure_rolls_back_and_stays_disabled", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.processes.commandLines())
		f.processes.rejectNextNetworkEnable()
		err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{bridge}})
		if err == nil {
			t.Fatal("network enable failure was ignored")
		}
		commands := f.processes.commandLines()[before:]
		if got := commands[len(commands)-1]; got != "SETCONF UseBridges=0 ClientTransportPlugin Bridge" {
			t.Fatalf("last command = %q, want rollback", got)
		}
		_ = d.Close()
		f.processes.waitForServers(t)
	})

	t.Run("rollback_failure_stays_disabled", func(t *testing.T) {
		f := newLifecycleFixture(t, "")
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.processes.commandLines())
		f.processes.rejectNextNetworkEnable()
		f.processes.rejectNextBridgeRollback()
		err = d.SetBridges(context.Background(), BridgeConfig{UseBridges: true, Bridges: []Bridge{bridge}})
		if err == nil || !strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("SetBridges() error = %v", err)
		}
		commands := f.processes.commandLines()[before:]
		if got := commands[len(commands)-1]; got != "SETCONF UseBridges=0 ClientTransportPlugin Bridge" {
			t.Fatalf("last command = %q, want failed rollback", got)
		}
		_ = d.Close()
		f.processes.waitForServers(t)
	})
}

func TestInjectedTerminalFailures(t *testing.T) {
	for _, stage := range []string{"lost control", "child crash"} {
		t.Run(strings.ReplaceAll(stage, " ", "_"), func(t *testing.T) {
			f := newLifecycleFixture(t, "")
			d, err := Start(context.Background(), f.cfg, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			proc := f.processes.process()
			if stage == "lost control" {
				proc.mu.Lock()
				_ = proc.conn.Close()
				proc.mu.Unlock()
			} else {
				proc.finish(errFixture)
			}
			select {
			case <-d.Done():
			case <-time.After(time.Second):
				t.Fatal("terminal failure did not close the driver")
			}
			if d.Err() == nil {
				t.Fatal("terminal cause was not recorded")
			}
			waited, _, released := proc.snapshot()
			if !waited || !released || !f.fs.wasRemoved() || f.local.count() != 0 {
				t.Fatalf("terminal cleanup incomplete: waited=%v released=%v removed=%v sockets=%d", waited, released, f.fs.wasRemoved(), f.local.count())
			}
			f.processes.waitForServers(t)
		})
	}
}

func TestConcurrentServiceCreateListenClose(t *testing.T) {
	f := newLifecycleFixture(t, "")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ready := make(chan struct{}, 32)
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			s, createErr := d.NewService(context.Background(), ServiceConfig{Ports: []uint16{80}})
			if createErr != nil {
				return
			}
			l, listenErr := s.Listen(context.Background(), "tcp", ":80")
			if listenErr == nil {
				_ = l.Close()
			}
			_ = s.Close()
		}()
	}
	for i := 0; i < 32; i++ {
		<-ready
	}
	close(start)
	_ = d.Close()
	wg.Wait()
	f.processes.waitForServers(t)
	if active := f.local.count(); active != 0 {
		t.Fatalf("%d local sockets remain active", active)
	}
}
