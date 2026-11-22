package tordriver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gobox"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/tor-driver/internal/control"
)

type eventTestLogger struct{ bytes.Buffer }

func (l *eventTestLogger) Debug(...any)          {}
func (l *eventTestLogger) Debugf(string, ...any) {}
func (l *eventTestLogger) Info(args ...any)      { _, _ = fmt.Fprint(l, args...) }
func (l *eventTestLogger) Infof(format string, args ...any) {
	_, _ = fmt.Fprintf(l, format, args...)
}
func (l *eventTestLogger) Warn(...any)           {}
func (l *eventTestLogger) Warnf(string, ...any)  {}
func (l *eventTestLogger) Err(...any)            {}
func (l *eventTestLogger) Errf(string, ...any)   {}
func (l *eventTestLogger) Fatal(...any)          {}
func (l *eventTestLogger) Fatalf(string, ...any) {}

func TestTypedDriverEventsOmitRawMessages(t *testing.T) {
	d := testDriver(&gonnect.RejectNetwork{})
	d.cfg.Transports = []TransportConfig{
		{Kind: "obfs4", Program: "transport"},
		{Kind: "go_pt", Dial: passthrough},
	}
	d.transportPaths = map[gobox.ProgramID]string{"transport": "/private/path"}
	d.activateBridges([]Bridge{{Transport: "obfs4"}, {Transport: "go_pt"}})
	if got := d.activeTransports(); len(got) != 1 || got[0].Kind != "obfs4" {
		t.Fatalf("managed transports for Tor events = %v", got)
	}
	events, cancel, err := d.SubscribeEvents(4)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	d.handleControlEvent(control.Event{Lines: []string{`STATUS_CLIENT WARN BOOTSTRAP PROGRESS=17 TAG=conn_pt SUMMARY="bridge 192.0.2.1 secret" WARNING="credential" REASON=PT_MISSING`}})
	d.handleControlEvent(control.Event{Lines: []string{`PT_LOG PT=/private/path SEVERITY=error MESSAGE="bridge password"`}})

	first := <-events
	bootstrap, ok := first.(BootstrapEvent)
	if !ok || bootstrap.Progress != 17 || bootstrap.Stage != "conn_pt" || bootstrap.Problem != "PT_MISSING" || bootstrap.Severity != EventWarning {
		t.Fatalf("bootstrap event = %#v", first)
	}
	for i := 0; i < 2; i++ {
		event := <-events
		transport, ok := event.(TransportEvent)
		if !ok || transport.Transport != "obfs4" || transport.State != TransportFailed {
			t.Fatalf("transport event = %#v", event)
		}
		if strings.Contains(strings.ToLower(string(transport.Transport)), "password") {
			t.Fatal("raw transport message was exposed")
		}
	}
}

func TestTransportEventsSelectOneActiveMethod(t *testing.T) {
	d := testDriver(&gonnect.RejectNetwork{})
	d.cfg.Transports = []TransportConfig{
		{Kind: "alpha", Program: "one"},
		{Kind: "beta", Program: "shared"},
		{Kind: "gamma", Program: "shared"},
	}
	d.transportPaths = map[gobox.ProgramID]string{"one": "/pt/one", "shared": "/pt/shared"}
	d.activateBridges([]Bridge{{Transport: "alpha"}, {Transport: "beta"}, {Transport: "gamma"}})
	for _, tc := range []struct {
		line string
		want Transport
	}{
		{"PT_LOG PT=/pt/one SEVERITY=error", "alpha"},
		{"PT_LOG PT=/pt/shared SEVERITY=error", ""},
		{"PT_STATUS PT=/pt/shared TRANSPORT=beta", "beta"},
		{"PT_STATUS PT=/pt/one TRANSPORT=gamma", ""},
		{"TRANSPORT_LAUNCHED client gamma 127.0.0.1 8000", "gamma"},
		{"TRANSPORT_LAUNCHED client inactive 127.0.0.1 8000", ""},
	} {
		before := len(d.recentEvents)
		d.handleControlEvent(control.Event{Lines: []string{tc.line}})
		events := d.recentEvents[before:]
		if tc.want == "" {
			if len(events) != 0 {
				t.Fatalf("%q produced %v", tc.line, events)
			}
		} else if len(events) != 1 || events[0].(TransportEvent).Transport != tc.want {
			t.Fatalf("%q produced %v, want %s", tc.line, events, tc.want)
		}
	}
}

func TestTerminalEventReportsTypedCause(t *testing.T) {
	f := newLifecycleFixture(t, "")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	events, cancel, err := d.SubscribeEvents(4)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	f.processes.process().finish(errFixture)
	deadline := time.After(time.Second)
	for {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("event subscription closed before terminal cause")
			}
			if terminal, match := event.(TerminalEvent); match {
				if terminal.Cause != TerminalProcessExit && terminal.Cause != TerminalControlConnection {
					t.Fatalf("terminal cause = %v", terminal.Cause)
				}
				if d.Err() == nil {
					t.Fatal("Driver.Err() did not retain the terminal error")
				}
				if terminal.Cause == TerminalProcessExit && !errors.Is(d.Err(), errFixture) {
					t.Fatalf("process exit error = %v", d.Err())
				}
				f.processes.waitForServers(t)
				return
			}
		case <-deadline:
			t.Fatal("terminal event was not delivered")
		}
	}
}

func TestOutboundFailureEventOmitsBackendDetails(t *testing.T) {
	d := testDriver(&gonnect.RejectNetwork{})
	d.gate.failurePolicy = LatchOutboundErrors
	events, cancel, err := d.SubscribeEvents(4)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	const secret = "backend credential 192.0.2.1"
	backend := &dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New(secret)
	}}
	if err = d.gate.replace(backend); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	_, _, _ = d.gate.dial(context.Background(), left, "198.51.100.2:443")

	event := <-events
	outbound, ok := event.(OutboundEvent)
	if !ok || outbound.Failure != OutboundDialFailed || !outbound.Latched || outbound.Generation == 0 {
		t.Fatalf("outbound event = %#v", event)
	}
	if strings.Contains(fmt.Sprint(event), secret) || strings.Contains(fmt.Sprint(event), "198.51.100.2") {
		t.Fatal("outbound event exposed backend or destination details")
	}
	cancel()
	replayed, replayCancel, err := d.SubscribeEvents(1)
	if err != nil {
		t.Fatal(err)
	}
	defer replayCancel()
	if _, ok = (<-replayed).(OutboundEvent); !ok {
		t.Fatal("recent outbound diagnostic was not retained")
	}
}

func TestShutdownEventReportsBoundedStage(t *testing.T) {
	f := newLifecycleFixture(t, "shutdown timeout")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	events, cancel, err := d.SubscribeEvents(32)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if err = d.Close(); err == nil {
		t.Fatal("Close() succeeded after a graceful shutdown timeout")
	}
	found := false
	for event := range events {
		if shutdown, ok := event.(ShutdownEvent); ok && shutdown.Stage == ShutdownGracefulWait {
			found = true
		}
	}
	if !found {
		t.Fatal("graceful shutdown diagnostic was not delivered")
	}
	f.processes.waitForServers(t)
}

func TestStartupErrorReportsStage(t *testing.T) {
	f := newLifecycleFixture(t, "control dial")
	_, err := Start(context.Background(), f.cfg, f.deps)
	var startup *StartupError
	if !errors.As(err, &startup) {
		t.Fatalf("Start() error = %v, want StartupError", err)
	}
	if startup.Stage != StartupControlConnection || !errors.Is(err, errFixture) {
		t.Fatalf("startup error = %#v (%v)", startup, err)
	}
	f.processes.waitForServers(t)
}

func TestTorLogWriterRedactsConfigurationAndPrivateKeys(t *testing.T) {
	logger := &eventTestLogger{}
	writer := &torLogRedactor{
		logger:        logger,
		enabled:       true,
		fixedSecrets:  []string{"user-secret"},
		bridgeSecrets: []string{"192.0.2.1:443", "bridge-certificate"},
	}
	stream := &torLogStream{logs: writer}
	line := "user-secret 192.0.2.1:443 bridge-certificate ED25519-V3:private-key descriptor:x25519:client-key\n"
	if _, err := stream.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	got := logger.String()
	for _, secret := range []string{"user-secret", "192.0.2.1:443", "bridge-certificate", "private-key", "client-key"} {
		if strings.Contains(got, secret) {
			t.Fatalf("forwarded Tor log contains %q: %q", secret, got)
		}
	}
}

func TestTorLogWriterRetainsEveryRuntimeBridgeSecret(t *testing.T) {
	logger := &eventTestLogger{}
	writer := &torLogRedactor{logger: logger, enabled: true, fixedSecrets: []string{"fixed-secret"}}
	stream := &torLogStream{logs: writer}
	first := []string{"198.51.100.1:443", "first-certificate"}
	second := []string{"203.0.113.2:8443", "second-certificate"}
	third := []string{"192.0.2.3:9443", "third-certificate"}
	writer.addBridgeSecrets(first)
	writer.addBridgeSecrets(second)
	writer.addBridgeSecrets(third)
	writer.addBridgeSecrets(append(first, "", second[0]))
	all := append(append(append([]string{"fixed-secret"}, first...), second...), third...)
	line := strings.Join(all, " ") + "\n"
	if _, err := stream.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	got := logger.String()
	for _, secret := range all {
		if strings.Contains(got, secret) {
			t.Fatalf("forwarded runtime Tor log contains %q: %q", secret, got)
		}
	}
	if gotCount, want := len(writer.bridgeSecrets), len(first)+len(second)+len(third); gotCount != want {
		t.Fatalf("retained bridge secret count = %d, want %d", gotCount, want)
	}
}

func TestTorLogWriterRetainsSecretsForPartialLineAcrossReplacement(t *testing.T) {
	logger := &eventTestLogger{}
	writer := &torLogRedactor{logger: logger, enabled: true}
	stream := &torLogStream{logs: writer}
	first := "198.51.100.10:443"
	second := "203.0.113.20:8443"
	writer.addBridgeSecrets([]string{first})
	if _, err := stream.Write([]byte("old bridge " + first)); err != nil {
		t.Fatal(err)
	}
	writer.addBridgeSecrets([]string{second})
	if _, err := stream.Write([]byte(" new bridge " + second + "\n")); err != nil {
		t.Fatal(err)
	}
	got := logger.String()
	for _, secret := range []string{first, second} {
		if strings.Contains(got, secret) {
			t.Fatalf("forwarded split Tor log contains %q: %q", secret, got)
		}
	}
}

func TestTorLogWriterRedactsCompleteDelayedLineAfterLaterReplacements(t *testing.T) {
	logger := &eventTestLogger{}
	writer := &torLogRedactor{logger: logger, enabled: true}
	stream := &torLogStream{logs: writer}
	first := "192.0.2.40:443"
	second := "198.51.100.50:8443"
	third := "203.0.113.60:9443"
	writer.addBridgeSecrets([]string{first})
	writer.addBridgeSecrets([]string{second})
	writer.addBridgeSecrets([]string{third})
	if _, err := stream.Write([]byte("delayed old bridge " + first + "\ncurrent bridge " + third + "\n")); err != nil {
		t.Fatal(err)
	}
	got := logger.String()
	for _, secret := range []string{first, second, third} {
		if strings.Contains(got, secret) {
			t.Fatalf("forwarded delayed Tor log contains %q: %q", secret, got)
		}
	}
}

func TestTorLogWriterRedactsEveryLineInOneWrite(t *testing.T) {
	logger := &eventTestLogger{}
	secret := "192.0.2.30:9001"
	writer := &torLogRedactor{logger: logger, enabled: true, bridgeSecrets: []string{secret}}
	stream := &torLogStream{logs: writer}
	if _, err := stream.Write([]byte("first " + secret + "\nsecond " + secret + "\n")); err != nil {
		t.Fatal(err)
	}
	got := logger.String()
	if strings.Contains(got, secret) {
		t.Fatalf("forwarded multi-line Tor log contains %q: %q", secret, got)
	}
	if count := strings.Count(got, "[redacted]"); count != 2 {
		t.Fatalf("redacted marker count = %d, want 2: %q", count, got)
	}
}

func TestTorLogWriterRedactsOverlappingSecrets(t *testing.T) {
	logger := &eventTestLogger{}
	writer := &torLogRedactor{logger: logger, enabled: true}
	stream := &torLogStream{logs: writer}
	writer.addBridgeSecrets([]string{"25519", "a", "abc", "cdef"})
	_, _ = stream.Write([]byte("ED25519-V3:private-key descriptor:x25519:client-key abcdef\n"))
	got := logger.String()
	if !strings.Contains(got, "ED[redacted]-V3:[redacted] descriptor:x[redacted]:[redacted] [redacted]") {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestTorLogWriterDropsTruncatedSecret(t *testing.T) {
	logger := &eventTestLogger{}
	writer := &torLogRedactor{logger: logger, enabled: true, bridgeSecrets: []string{"private-value"}}
	stream := &torLogStream{logs: writer}
	_, _ = stream.Write([]byte(strings.Repeat(" ", 8185) + "private"))
	_, _ = stream.Write([]byte("-value\nready\n"))
	if got := logger.String(); got != "tor: [truncated]tor: ready" {
		t.Fatalf("unexpected truncated log: %q", got)
	}
}

func TestTorLogStreamsRedactInterleavedOutput(t *testing.T) {
	logger := &eventTestLogger{}
	logs := &torLogRedactor{logger: logger, enabled: true}
	stdout := &torLogStream{logs: logs}
	stderr := &torLogStream{logs: logs}
	_, _ = stdout.Write([]byte("bridge pass"))
	_, _ = stderr.Write([]byte("ready\n"))
	fp := strings.Repeat("ab", 20)
	logs.addBridgeSecrets(bridgeLogSecrets([]Bridge{{Fingerprint: Fingerprint(fp), Args: map[string]string{"secret": "passcode"}}}))
	_, _ = stdout.Write([]byte("code " + strings.ToUpper(fp) + "\n"))
	if got := logger.String(); got != "tor: readytor: bridge [redacted] [redacted]" {
		t.Fatalf("unexpected forwarded lines: %q", got)
	}
}
