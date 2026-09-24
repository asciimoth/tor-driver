package tordriver

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type EventSeverity uint8

const (
	EventNotice EventSeverity = iota
	EventWarning
	EventError
)

// DriverEvent is a bounded, typed status event. It does not contain raw Tor
// control-event text.
type DriverEvent interface {
	driverEvent()
}

type BootstrapStage string
type BootstrapProblem string

// BootstrapEvent reports Tor's current bootstrap percentage and stable tokens.
// Human-readable Tor messages, relay addresses, and bridge details are omitted.
type BootstrapEvent struct {
	Progress uint8
	Stage    BootstrapStage
	Severity EventSeverity
	Problem  BootstrapProblem
}

func (BootstrapEvent) driverEvent() {}

type TransportState uint8

const (
	TransportStarting TransportState = iota
	TransportReady
	TransportFailed
)

// TransportEvent reports managed-transport state without the executable path,
// bridge address, or raw transport log message.
type TransportEvent struct {
	Transport Transport
	State     TransportState
	Severity  EventSeverity
}

func (TransportEvent) driverEvent() {}

type TerminalCause uint8

const (
	TerminalProcessExit TerminalCause = iota
	TerminalControlConnection
	TerminalProxyListener
)

// TerminalEvent reports why the owned Driver became terminal.
type TerminalEvent struct {
	Cause TerminalCause
}

func (TerminalEvent) driverEvent() {}

// OutboundFailure identifies a failure at the outgoing Network boundary.
// It does not contain a destination, backend error, or network configuration.
type OutboundFailure uint8

const (
	OutboundAttachmentRejected OutboundFailure = iota
	OutboundAttachmentClosed
	OutboundDialFailed
	OutboundStreamFailed
)

// OutboundEvent reports an outgoing attachment failure. Generation matches
// OutboundState.Generation. Latched reports that explicit SetOutbound is
// required before Tor can make another outgoing connection.
type OutboundEvent struct {
	Failure    OutboundFailure
	Generation uint64
	Latched    bool
}

func (OutboundEvent) driverEvent() {}

// ShutdownStage identifies a cleanup stage that returned an error.
type ShutdownStage uint8

const (
	ShutdownOutbound ShutdownStage = iota
	ShutdownResources
	ShutdownControl
	ShutdownGracefulWait
	ShutdownKill
	ShutdownForcedWait
	ShutdownProcessRelease
	ShutdownProxy
	ShutdownTemporaryFiles
)

// ShutdownEvent reports a shutdown failure without exposing the raw error or
// resource names. Close returns the complete error to its caller.
type ShutdownEvent struct {
	Stage ShutdownStage
}

func (ShutdownEvent) driverEvent() {}

// StartupStage identifies the operation that prevented Start from completing.
type StartupStage uint8

const (
	StartupValidation StartupStage = iota
	StartupWorkingDirectory
	StartupStateDirectory
	StartupProxyCredentials
	StartupProxyListener
	StartupConfiguration
	StartupProcess
	StartupControlEndpoint
	StartupControlConnection
	StartupAuthentication
	StartupControlOwnership
	StartupEventSubscription
	StartupProxyVerification
	StartupEnableNetwork
	StartupSOCKSListener
)

var startupStageNames = [...]string{
	"configuration validation",
	"working directory setup",
	"state directory setup",
	"local proxy credential setup",
	"local proxy listener setup",
	"Tor configuration setup",
	"Tor process start",
	"control endpoint discovery",
	"control connection setup",
	"control authentication",
	"control ownership setup",
	"control event setup",
	"upstream proxy verification",
	"network enablement",
	"SOCKS listener discovery",
}

func (s StartupStage) String() string {
	if int(s) >= len(startupStageNames) {
		return "unknown stage"
	}
	return startupStageNames[s]
}

// StartupError reports a bounded startup stage and retains the original error
// for errors.Is and errors.As. It does not add configuration values to Error.
type StartupError struct {
	Stage StartupStage
	Err   error
}

func (e *StartupError) Error() string {
	return fmt.Sprintf("tor-driver: startup failed during %s: %v", e.Stage, e.Err)
}

func (e *StartupError) Unwrap() error { return e.Err }

func newStartupError(stage StartupStage, err error) error {
	if err == nil {
		return nil
	}
	var existing *StartupError
	if errors.As(err, &existing) {
		return err
	}
	return &StartupError{Stage: stage, Err: err}
}

// ServiceEvent is a typed onion-service lifecycle event.
type ServiceEvent interface {
	serviceEvent()
}

type PublicationState uint8

const (
	PublicationPending PublicationState = iota
	PublicationPublished
	PublicationFailed
)

type PublicationProblem string

// PublicationEvent reports descriptor upload state. Directory identities and
// descriptor identifiers are intentionally omitted.
type PublicationEvent struct {
	State   PublicationState
	Problem PublicationProblem
}

func (PublicationEvent) serviceEvent() {}

type eventBroker[T any] struct {
	mu     sync.Mutex
	closed bool
	next   uint64
	subs   map[uint64]chan T
}

func newEventBroker[T any]() *eventBroker[T] {
	return &eventBroker[T]{subs: make(map[uint64]chan T)}
}

func (b *eventBroker[T]) subscribeInitial(buffer int, initial []T) (chan T, func(), error) {
	if buffer < 1 || buffer > 1024 {
		return nil, nil, fmt.Errorf("tor-driver: event buffer must be between 1 and 1024")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil, ErrClosed
	}
	id := b.next
	b.next++
	ch := make(chan T, buffer)
	if len(initial) > buffer {
		initial = initial[len(initial)-buffer:]
	}
	for _, event := range initial {
		ch <- event
	}
	b.subs[id] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			if existing, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(existing)
			}
			b.mu.Unlock()
		})
	}, nil
}

// publish retains recent state for a slow subscriber. Internal readiness does
// not depend on subscription delivery.
func (b *eventBroker[T]) publish(event T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	for _, ch := range b.subs {
		select {
		case ch <- event:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- event:
			default:
			}
		}
	}
}

func (b *eventBroker[T]) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for id, ch := range b.subs {
		delete(b.subs, id)
		close(ch)
	}
}

func eventSeverity(value string) (EventSeverity, bool) {
	switch strings.ToUpper(value) {
	case "NOTICE", "INFO", "DEBUG":
		return EventNotice, true
	case "WARN", "WARNING":
		return EventWarning, true
	case "ERR", "ERROR":
		return EventError, true
	default:
		return EventNotice, false
	}
}

func controlWords(line string) ([]string, error) {
	var words []string
	for i := 0; i < len(line); {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i == len(line) {
			break
		}
		start := i
		quoted := false
		escaped := false
		for i < len(line) {
			c := line[i]
			if escaped {
				escaped = false
				i++
				continue
			}
			if quoted && c == '\\' {
				escaped = true
				i++
				continue
			}
			if c == '"' {
				quoted = !quoted
				i++
				continue
			}
			if c == ' ' && !quoted {
				break
			}
			i++
		}
		if quoted || escaped {
			return nil, fmt.Errorf("tor-driver: malformed control status event")
		}
		words = append(words, line[start:i])
	}
	return words, nil
}

func eventArguments(words []string) map[string]string {
	result := make(map[string]string)
	for _, word := range words {
		key, value, ok := strings.Cut(word, "=")
		if !ok || !safeEventToken(key) {
			continue
		}
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				continue
			}
			value = decoded
		}
		result[key] = value
	}
	return result
}

func safeEventToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
