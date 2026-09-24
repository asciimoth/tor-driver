package tordriver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/tor-driver/internal/control"
)

type Driver struct {
	cfg           Config
	deps          Dependencies
	work          string
	proc          Process
	control       *control.Client
	socks         string
	socksMu       sync.RWMutex
	gate          *outboundGate
	proxy         *proxyServer
	logs          *torLogWriter
	resources     *scope
	mu            sync.Mutex
	closed        bool
	networks      map[*Network]struct{}
	services      map[*Service]struct{}
	keyNames      map[string]struct{}
	events        *eventBroker[DriverEvent]
	recentEvents  []DriverEvent
	descriptors   map[string]PublicationEvent
	bootstrap     BootstrapEvent
	haveBootstrap bool
	randomMu      sync.Mutex
	configMu      sync.Mutex
	approvedPT    []TransportConfig
	processDone   chan struct{}
	processErr    error
	err           error
	closeOnce     sync.Once
	done          chan struct{}
	closeErr      error
}

// Start owns one foreground Tor daemon. ctx bounds startup only; Close owns
// the resulting lifetime. Start succeeds before bootstrap, even with nil
// Outbound. WaitReady separately waits for an actual usable Tor connection.
func Start(ctx context.Context, cfg Config, deps Dependencies) (_ *Driver, err error) {
	stage := StartupValidation
	var d *Driver
	defer func() {
		if err == nil {
			return
		}
		if d != nil {
			err = errors.Join(err, d.Close())
		}
		err = newStartupError(stage, err)
	}()
	cfg, err = validate(cfg, deps)
	if err != nil {
		return nil, err
	}
	d = &Driver{cfg: cfg, deps: deps, gate: &outboundGate{}, resources: newScope(), networks: make(map[*Network]struct{}), services: make(map[*Service]struct{}), keyNames: make(map[string]struct{}), events: newEventBroker[DriverEvent](), descriptors: make(map[string]PublicationEvent), approvedPT: append([]TransportConfig(nil), cfg.Transports...), processDone: make(chan struct{}), done: make(chan struct{})}
	d.gate.notify = func(event OutboundEvent) { d.publishDriverEvent(event) }
	d.gate.failurePolicy = cfg.OutboundFailures
	ctx, cancel := deps.Clock.Timeout(ctx, cfg.StartupTimeout)
	defer cancel()
	stage = StartupWorkingDirectory
	d.work, err = deps.FS.TempDir(cfg.TempRoot, "tor-driver-")
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(d.work) || !safeText(d.work) {
		return nil, fmt.Errorf("tor-driver: adapter returned invalid temporary path")
	}
	if err = deps.FS.PrivateDir(d.work, cfg.Identity); err != nil {
		return nil, err
	}
	stage = StartupStateDirectory
	state := cfg.StateDirectory
	if state == "" {
		state = filepath.Join(d.work, "state")
	}
	if err = deps.FS.PrivateDir(state, cfg.Identity); err != nil {
		return nil, err
	}
	if err = d.gate.replace(deps.Outbound); err != nil {
		// A dead initial network is equivalent to no network; Tor remains owned
		// and can recover through a later SetOutbound.
		deps.Logger.Warn("tor-driver: initial outbound network unavailable")
	}
	stage = StartupProxyCredentials
	user, err := d.token()
	if err != nil {
		return nil, err
	}
	password, err := d.token()
	if err != nil {
		return nil, err
	}
	stage = StartupProxyListener
	l, err := deps.LocalNetwork.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if _, err = numericEndpoint(l.Addr().String(), true); err != nil {
		_ = l.Close()
		return nil, err
	}
	d.proxy = startProxy(l, d.gate, deps.Clock, cfg.DialTimeout, cfg.MaxProxyConnections, user, password)
	stage = StartupConfiguration
	torrc := filepath.Join(d.work, "torrc")
	defaults := filepath.Join(d.work, "defaults-torrc")
	if err = deps.FS.WriteFile(defaults, nil, 0600, cfg.Identity); err != nil {
		return nil, err
	}
	text := renderConfig(cfg, d.work, state, l.Addr().String(), user, password, deps.Processes.PID())
	if err = deps.FS.WriteFile(torrc, []byte(text), 0600, cfg.Identity); err != nil {
		return nil, err
	}
	d.logs = &torLogWriter{
		logger:        deps.Logger,
		enabled:       cfg.ForwardTorLogs,
		fixedSecrets:  startupLogSecrets(cfg, user, password),
		bridgeSecrets: bridgeLogSecrets(cfg.Bridges),
	}
	stage = StartupProcess
	d.proc, err = deps.Processes.Start(ctx, Launch{Executable: cfg.TorExecutable, Args: []string{"--defaults-torrc", defaults, "-f", torrc}, Directory: d.work, Identity: cfg.Identity, Stdout: d.logs, Stderr: d.logs})
	if err != nil {
		return nil, err
	}
	go func() { e := d.proc.Wait(); d.mu.Lock(); d.processErr = e; d.mu.Unlock(); close(d.processDone) }()
	stage = StartupControlEndpoint
	portFile, err := d.waitFile(ctx, filepath.Join(d.work, "control-port"), 4096)
	if err != nil {
		return nil, err
	}
	port := ""
	for _, line := range strings.Split(string(portFile), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "PORT="); ok {
			port = p
		}
	}
	if _, err = numericEndpoint(port, true); err != nil {
		return nil, fmt.Errorf("tor-driver: invalid control endpoint")
	}
	stage = StartupControlConnection
	conn, err := deps.LocalNetwork.Dial(ctx, "tcp", port)
	if err != nil {
		return nil, err
	}
	d.control = control.New(conn)
	stage = StartupAuthentication
	cookie, err := d.waitFile(ctx, filepath.Join(d.work, "control-cookie"), 32)
	if err != nil {
		return nil, err
	}
	d.randomMu.Lock()
	err = d.control.Authenticate(ctx, cookie, deps.Random)
	d.randomMu.Unlock()
	clear(cookie)
	if err != nil {
		return nil, err
	}
	stage = StartupControlOwnership
	for _, cmd := range []string{"TAKEOWNERSHIP", "RESETCONF __OwningControllerProcess"} {
		if _, err = d.control.Do(ctx, cmd); err != nil {
			return nil, err
		}
	}
	go d.controlEventLoop()
	stage = StartupEventSubscription
	if _, err = d.control.Do(ctx, "USEFEATURE EXTENDED_EVENTS VERBOSE_NAMES"); err != nil {
		return nil, fmt.Errorf("tor-driver: enable typed control events: %w", err)
	}
	r, err := d.control.Do(ctx, "GETINFO events/names")
	if err != nil {
		return nil, fmt.Errorf("tor-driver: query control events: %w", err)
	}
	eventNames, ok := control.Value(r, "events/names")
	if !ok {
		return nil, fmt.Errorf("tor-driver: Tor did not report supported control events")
	}
	supportedEvents := make(map[string]struct{})
	for _, name := range strings.Fields(eventNames) {
		supportedEvents[name] = struct{}{}
	}
	selectedEvents := make([]string, 0, 5)
	for _, name := range []string{"STATUS_CLIENT", "HS_DESC", "TRANSPORT_LAUNCHED", "PT_LOG", "PT_STATUS"} {
		if _, supported := supportedEvents[name]; supported {
			selectedEvents = append(selectedEvents, name)
		}
	}
	if _, statusEvents := supportedEvents["STATUS_CLIENT"]; !statusEvents {
		return nil, fmt.Errorf("tor-driver: Tor does not support typed bootstrap events")
	}
	if _, descriptorEvents := supportedEvents["HS_DESC"]; !descriptorEvents {
		return nil, fmt.Errorf("tor-driver: Tor does not support descriptor publication events")
	}
	if _, err = d.control.Do(ctx, "SETEVENTS "+strings.Join(selectedEvents, " ")); err != nil {
		return nil, fmt.Errorf("tor-driver: subscribe to typed control events: %w", err)
	}
	r, err = d.control.Do(ctx, "GETINFO status/bootstrap-phase")
	if err != nil {
		return nil, err
	}
	if phase, ok := control.Value(r, "status/bootstrap-phase"); ok {
		d.handleControlEvent(control.Event{Lines: []string{"STATUS_CLIENT " + phase}})
	}
	// Confirm the fixed upstream proxy before allowing bootstrap.
	stage = StartupProxyVerification
	r, err = d.control.Do(ctx, "GETCONF Socks5Proxy")
	if err != nil {
		return nil, err
	}
	if p, ok := control.Value(r, "Socks5Proxy"); !ok || p != l.Addr().String() {
		return nil, fmt.Errorf("tor-driver: Tor did not retain the mandatory upstream proxy")
	}
	stage = StartupEnableNetwork
	if _, err = d.control.Do(ctx, "SETCONF DisableNetwork=0"); err != nil {
		return nil, err
	}
	stage = StartupSOCKSListener
	if d.socks, err = d.querySocksEndpoint(ctx); err != nil {
		return nil, err
	}
	deps.Logger.Info("tor-driver: Tor started; control authenticated")
	go d.monitor()
	return d, nil
}
func (d *Driver) token() (string, error) {
	d.randomMu.Lock()
	defer d.randomMu.Unlock()
	var b [32]byte
	if _, err := io.ReadFull(d.deps.Random, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (d *Driver) waitFile(ctx context.Context, path string, max int64) ([]byte, error) {
	for {
		b, err := d.deps.FS.ReadFile(path, max)
		if err == nil && len(b) > 0 {
			return b, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) && !retryableFileReadError(err) {
			return nil, err
		}
		select {
		case <-d.processDone:
			d.mu.Lock()
			processErr := d.processErr
			d.mu.Unlock()
			return nil, errors.Join(fmt.Errorf("tor-driver: Tor exited during startup"), processErr)
		default:
		}
		if err = d.deps.Clock.Sleep(ctx, 25*time.Millisecond); err != nil {
			return nil, err
		}
	}
}
func (d *Driver) monitor() {
	var cause error
	var terminal TerminalCause
	select {
	case <-d.processDone:
		d.mu.Lock()
		processErr := d.processErr
		d.mu.Unlock()
		cause = errors.Join(fmt.Errorf("tor-driver: Tor exited unexpectedly"), processErr)
		terminal = TerminalProcessExit
	case <-d.control.Done():
		cause = fmt.Errorf("tor-driver: control connection lost")
		terminal = TerminalControlConnection
	case <-d.proxy.done:
		cause = fmt.Errorf("tor-driver: upstream proxy listener stopped")
		terminal = TerminalProxyListener
	case <-d.done:
		return
	}
	d.mu.Lock()
	if !d.closed {
		d.err = cause
	}
	d.mu.Unlock()
	if d.events != nil {
		d.publishDriverEvent(TerminalEvent{Cause: terminal})
	}
	_ = d.Close()
}
func (d *Driver) command(ctx context.Context, cmd string) (control.Reply, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return control.Reply{}, ErrClosed
	}
	ctx, cancel := d.deps.Clock.Timeout(ctx, d.cfg.CommandTimeout)
	defer cancel()
	return d.control.Do(ctx, cmd)
}

func (d *Driver) querySocksEndpoint(ctx context.Context) (string, error) {
	r, err := d.control.Do(ctx, "GETINFO net/listeners/socks")
	if err != nil {
		return "", err
	}
	v, ok := control.Value(r, "net/listeners/socks")
	if !ok {
		return "", fmt.Errorf("tor-driver: Tor did not report a SOCKS listener")
	}
	endpoints, err := control.QuotedWords(v)
	if err != nil || len(endpoints) != 1 {
		return "", fmt.Errorf("tor-driver: expected exactly one SOCKS endpoint")
	}
	if _, err = numericEndpoint(endpoints[0], true); err != nil {
		return "", err
	}
	return endpoints[0], nil
}

func (d *Driver) socksEndpoint() string {
	d.socksMu.RLock()
	defer d.socksMu.RUnlock()
	return d.socks
}
func (d *Driver) WaitReady(ctx context.Context) error {
	for {
		r, err := d.command(ctx, "GETINFO status/circuit-established")
		if err != nil {
			return err
		}
		if v, ok := control.Value(r, "status/circuit-established"); ok && v == "1" && d.gate.state().Available {
			return nil
		}
		if err = d.deps.Clock.Sleep(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
}

// SetOutbound drops both sides of all old proxy sessions and cancels pending
// dials before installing n. Even reinstalling the same n starts a new epoch.
// A failed install leaves the driver blocked. Supplied networks stay caller-owned.
func (d *Driver) SetOutbound(n gonnect.Network) error {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if loop, ok := n.(*Network); ok && loop.d == d {
		_ = d.gate.replace(nil)
		return fmt.Errorf("tor-driver: cannot use own Tor network as outbound")
	}
	err := d.gate.replace(n)
	if err == nil {
		d.deps.Logger.Debug("tor-driver: outbound network replaced")
	}
	return err
}

// SetBridges replaces the complete bridge and managed-transport configuration.
// It stops Tor networking before the change. SETCONF applies all bridge values
// atomically. A failed change or rollback leaves Tor networking disabled.
func (d *Driver) SetBridges(ctx context.Context, cfg BridgeConfig) error {
	bridges, transports, err := validateBridgeConfig(cfg.UseBridges, cfg.Bridges, cfg.Transports, d.cfg.Sandbox, d.deps.Logger)
	if err != nil {
		return err
	}
	for _, transport := range transports {
		if !slices.Contains(d.approvedPT, transport) {
			return fmt.Errorf("tor-driver: runtime transport was not approved at Start")
		}
	}
	d.configMu.Lock()
	defer d.configMu.Unlock()
	old := BridgeConfig{UseBridges: d.cfg.UseBridges, Bridges: d.cfg.Bridges, Transports: d.cfg.Transports}
	if _, err = d.command(ctx, "SETCONF DisableNetwork=1"); err != nil {
		disableErr := fmt.Errorf("tor-driver: disable networking before bridge change: %w", err)
		if cfg.UseBridges && !old.UseBridges {
			return errors.Join(disableErr, d.Close())
		}
		return disableErr
	}
	desired := BridgeConfig{UseBridges: cfg.UseBridges, Bridges: bridges, Transports: transports}
	// Keep every configuration redacted for the process lifetime. Tor log
	// delivery can lag behind SETCONF completion and later replacements.
	d.logs.addBridgeSecrets(append(bridgeLogSecrets(old.Bridges), bridgeLogSecrets(desired.Bridges)...))
	if _, err = d.command(ctx, bridgeSetCommand(desired)); err != nil {
		return fmt.Errorf("tor-driver: bridge change rejected; networking remains disabled: %w", err)
	}
	if _, err = d.command(ctx, "SETCONF DisableNetwork=0"); err != nil {
		return errors.Join(
			fmt.Errorf("tor-driver: enable networking after bridge change: %w", err),
			d.rollbackBridges(old, desired),
		)
	}
	endpoint, endpointErr := d.command(ctx, "GETINFO net/listeners/socks")
	if endpointErr == nil {
		endpointErr = d.applySocksReply(endpoint)
	}
	if endpointErr != nil {
		disableCtx, cancel := d.deps.Clock.Timeout(context.Background(), d.cfg.CommandTimeout)
		_, disableErr := d.control.Do(disableCtx, "SETCONF DisableNetwork=1")
		cancel()
		rollbackErr := d.rollbackBridges(old, desired)
		if disableErr != nil {
			disableErr = errors.Join(fmt.Errorf("tor-driver: disable networking after SOCKS listener failure: %w", disableErr), d.Close())
		}
		return errors.Join(fmt.Errorf("tor-driver: refresh SOCKS listener after bridge change: %w", endpointErr), disableErr, rollbackErr)
	}
	d.cfg.UseBridges, d.cfg.Bridges, d.cfg.Transports = desired.UseBridges, desired.Bridges, desired.Transports
	d.deps.Logger.Info("tor-driver: bridge configuration replaced")
	return nil
}

func (d *Driver) applySocksReply(reply control.Reply) error {
	v, ok := control.Value(reply, "net/listeners/socks")
	if !ok {
		return fmt.Errorf("tor-driver: Tor did not report a SOCKS listener")
	}
	endpoints, err := control.QuotedWords(v)
	if err != nil || len(endpoints) != 1 {
		return fmt.Errorf("tor-driver: expected exactly one SOCKS endpoint")
	}
	if _, err = numericEndpoint(endpoints[0], true); err != nil {
		return err
	}
	d.socksMu.Lock()
	d.socks = endpoints[0]
	d.socksMu.Unlock()
	return nil
}

func (d *Driver) rollbackBridges(old, desired BridgeConfig) error {
	rollbackCtx, cancel := d.deps.Clock.Timeout(context.Background(), d.cfg.CommandTimeout)
	_, err := d.control.Do(rollbackCtx, bridgeSetCommand(old))
	cancel()
	if err != nil {
		d.cfg.UseBridges, d.cfg.Bridges, d.cfg.Transports = desired.UseBridges, desired.Bridges, desired.Transports
	}
	return wrapRollbackError(err)
}

func wrapRollbackError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("tor-driver: bridge rollback failed; networking remains disabled: %w", err)
}

func bridgeSetCommand(cfg BridgeConfig) string {
	parts := []string{"SETCONF", "UseBridges=" + strconv.Itoa(bit(cfg.UseBridges))}
	if len(cfg.Transports) == 0 {
		parts = append(parts, "ClientTransportPlugin")
	} else {
		for _, transport := range cfg.Transports {
			parts = append(parts, "ClientTransportPlugin="+quote("obfs4 exec "+transport.Executable))
		}
	}
	lines := bridgeLines(cfg.Bridges)
	if len(lines) == 0 {
		parts = append(parts, "Bridge")
	} else {
		for _, bridge := range lines {
			parts = append(parts, "Bridge="+quote(bridge))
		}
	}
	return strings.Join(parts, " ")
}
func (d *Driver) OutboundState() OutboundState { return d.gate.state() }
func (d *Driver) Done() <-chan struct{}        { return d.done }
func (d *Driver) Err() error                   { d.mu.Lock(); defer d.mu.Unlock(); return d.err }

// SubscribeEvents returns recent typed Driver status events. A slow subscriber
// keeps the newest buffered events. cancel removes this subscription.
func (d *Driver) SubscribeEvents(buffer int) (<-chan DriverEvent, func(), error) {
	if d.events == nil {
		return nil, nil, ErrClosed
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, nil, ErrClosed
	}
	initial := append([]DriverEvent(nil), d.recentEvents...)
	ch, cancel, err := d.events.subscribeInitial(buffer, initial)
	d.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	return ch, cancel, nil
}

// Close is concurrent-safe and idempotent. It blocks outbound traffic first,
// closes all application resources, requests shutdown, then kills/reaps Tor.
// It reports a graceful-shutdown timeout and all observable cleanup failures.
func (d *Driver) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		d.recordCloseError(ShutdownOutbound, d.gate.Close())
		d.recordCloseError(ShutdownResources, d.resources.Close())
		if d.control != nil {
			ctx, cancel := d.deps.Clock.Timeout(context.Background(), d.cfg.ShutdownTimeout)
			_, signalErr := d.control.Do(ctx, "SIGNAL SHUTDOWN")
			cancel()
			d.recordCloseError(ShutdownControl, signalErr)
			d.recordCloseError(ShutdownControl, d.control.Close())
		}
		reaped := d.proc == nil
		forced := false
		if d.proc != nil {
			ctx, cancel := d.deps.Clock.Timeout(context.Background(), d.cfg.ShutdownTimeout)
			select {
			case <-d.processDone:
				reaped = true
			case <-ctx.Done():
				d.recordCloseError(ShutdownGracefulWait, fmt.Errorf("tor-driver: graceful shutdown timed out"))
			}
			cancel()
			if !reaped {
				forced = true
				d.recordCloseError(ShutdownKill, d.proc.Kill())
				ctx, cancel = d.deps.Clock.Timeout(context.Background(), d.cfg.ShutdownTimeout)
				select {
				case <-d.processDone:
					reaped = true
				case <-ctx.Done():
					d.recordCloseError(ShutdownForcedWait, fmt.Errorf("tor-driver: process did not exit after Kill"))
				}
				cancel()
			}
			if reaped {
				if !forced {
					d.mu.Lock()
					processErr := d.processErr
					d.mu.Unlock()
					d.recordCloseError(ShutdownGracefulWait, processErr)
				}
				d.recordCloseError(ShutdownProcessRelease, d.proc.Release())
			}
		}
		if d.proxy != nil {
			d.recordCloseError(ShutdownProxy, d.proxy.Close())
		}
		if reaped && d.work != "" {
			d.recordCloseError(ShutdownTemporaryFiles, d.deps.FS.RemoveAll(d.work))
		}
		d.mu.Lock()
		d.networks = nil
		d.services = nil
		d.keyNames = nil
		d.mu.Unlock()
		if d.events != nil {
			d.events.close()
		}
		close(d.done)
	})
	return d.closeErr
}

func (d *Driver) publishDriverEvent(event DriverEvent) {
	d.mu.Lock()
	const recentLimit = 32
	if len(d.recentEvents) == recentLimit {
		copy(d.recentEvents, d.recentEvents[1:])
		d.recentEvents[len(d.recentEvents)-1] = event
	} else {
		d.recentEvents = append(d.recentEvents, event)
	}
	d.mu.Unlock()
	d.events.publish(event)
}

func (d *Driver) recordCloseError(stage ShutdownStage, err error) {
	if err == nil {
		return
	}
	d.closeErr = errors.Join(d.closeErr, err)
	d.publishDriverEvent(ShutdownEvent{Stage: stage})
}

type torLogWriter struct {
	mu            sync.Mutex
	logger        Logger
	enabled       bool
	buffer        []byte
	fixedSecrets  []string
	bridgeSecrets []string
	bufferSecrets []string
}

func startupLogSecrets(cfg Config, user, password string) []string {
	secrets := []string{user, password, cfg.TorExecutable}
	for _, transport := range cfg.Transports {
		secrets = append(secrets, transport.Executable)
	}
	return secrets
}

func bridgeLogSecrets(bridges []Bridge) []string {
	secrets := make([]string, 0, len(bridges)*4)
	for _, bridge := range bridges {
		secrets = append(secrets, bridge.Address, string(bridge.Fingerprint), bridge.Obfs4Certificate)
	}
	secrets = append(secrets, bridgeLines(bridges)...)
	return secrets
}

func (w *torLogWriter) addBridgeSecrets(secrets []string) {
	w.mu.Lock()
	for _, secret := range secrets {
		if secret != "" && !slices.Contains(w.bridgeSecrets, secret) {
			w.bridgeSecrets = append(w.bridgeSecrets, secret)
		}
	}
	w.mu.Unlock()
}

func redactToken(line, prefix string) string {
	search := 0
	for {
		relative := strings.Index(line[search:], prefix)
		if relative < 0 {
			return line
		}
		start := search + relative
		end := start + len(prefix)
		for end < len(line) && line[end] != ' ' && line[end] != '\t' {
			end++
		}
		line = line[:start] + prefix + "[redacted]" + line[end:]
		search = start + len(prefix) + len("[redacted]")
	}
}

func (w *torLogWriter) Write(b []byte) (int, error) {
	if !w.enabled || len(b) == 0 {
		return len(b), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rememberSecrets := func() {
		for _, secret := range w.bridgeSecrets {
			if secret != "" && !slices.Contains(w.bufferSecrets, secret) {
				w.bufferSecrets = append(w.bufferSecrets, secret)
			}
		}
	}
	rememberSecrets()
	for i, c := range b {
		if c == '\n' {
			line := strings.TrimSpace(string(w.buffer))
			w.buffer = w.buffer[:0]
			redact := func(secrets []string) {
				for _, secret := range secrets {
					if secret != "" {
						line = strings.ReplaceAll(line, secret, "[redacted]")
					}
				}
			}
			redact(w.fixedSecrets)
			redact(w.bufferSecrets)
			w.bufferSecrets = w.bufferSecrets[:0]
			line = redactToken(line, "ED25519-V3:")
			line = redactToken(line, "descriptor:x25519:")
			w.logger.Infof("tor: %s", line)
			if i+1 < len(b) {
				rememberSecrets()
			}
		} else if len(w.buffer) < 8192 {
			w.buffer = append(w.buffer, c)
		}
	}
	return len(b), nil
}

var _ io.Closer = (*Driver)(nil)
var _ net.Conn = (*ownedConn)(nil)
