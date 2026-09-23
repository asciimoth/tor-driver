package tordriver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/tor-driver/internal/control"
)

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
