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
	d.cfg.Transports = []TransportConfig{{Kind: Obfs4, Executable: "/transport"}}
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
		if !ok || transport.Transport != Obfs4 || transport.State != TransportFailed {
			t.Fatalf("transport event = %#v", event)
		}
		if strings.Contains(strings.ToLower(string(transport.Transport)), "password") {
			t.Fatal("raw transport message was exposed")
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
	writer := &torLogWriter{
		logger:  logger,
		enabled: true,
		secrets: []string{"user-secret", "192.0.2.1:443", "bridge-certificate"},
	}
	line := "user-secret 192.0.2.1:443 bridge-certificate ED25519-V3:private-key descriptor:x25519:client-key\n"
	if _, err := writer.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	got := logger.String()
	for _, secret := range []string{"user-secret", "192.0.2.1:443", "bridge-certificate", "private-key", "client-key"} {
		if strings.Contains(got, secret) {
			t.Fatalf("forwarded Tor log contains %q: %q", secret, got)
		}
	}
}
