// Package tordriver owns a Tor client process and exposes isolated gonnect
// networks and v3 onion services. It never supplies a default egress.
package tordriver

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/asciimoth/gobox"
	"github.com/asciimoth/gonnect"
)

var (
	ErrClosed               = errors.New("tor-driver: closed")
	ErrUnsupported          = errors.New("tor-driver: unsupported operation")
	ErrOutboundUnavailable  = errors.New("tor-driver: outbound network unavailable")
	ErrUnsupportedTransport = errors.New("tor-driver: unsupported transport")
)

// Logger implementations must be safe for concurrent use. Driver never calls
// Fatal/Fatalf: a library must not terminate its host process.
type Logger interface {
	Debug(args ...any)
	Debugf(format string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Warn(args ...any)
	Warnf(format string, args ...any)
	Err(args ...any)
	Errf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Clock abstracts wall time and timers used by the driver. Go's scheduler and
// synchronization primitives are intentionally not replaced.
type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
	Timeout(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

// Dependencies are borrowed. Driver closes the sandbox instance that it
// acquires, but it does not close Sandboxes, Outbound, Logger, Clock, or Random.
type Dependencies struct {
	Sandboxes gobox.OwnerSandboxes
	Clock     Clock
	Random    io.Reader
	Logger    Logger
	Outbound  gonnect.Network // nil starts with blocked outbound traffic
	OnionKeys OnionKeyStore   // required only by a named persistent service
}

type SandboxMode uint8

const (
	// DynamicServices allows runtime ADD_ONION; Tor's seccomp sandbox is off.
	DynamicServices SandboxMode = iota
	// LinuxSandbox requires a libseccomp-enabled Tor and forbids ADD_ONION.
	LinuxSandbox
)

type LogLevel uint8

const (
	LogNotice LogLevel = iota
	LogWarn
	LogError
)

// ConnectionPaddingPolicy controls padding between Tor and relays.
type ConnectionPaddingPolicy uint8

const (
	// NegotiatedConnectionPadding uses padding when the relay supports it.
	NegotiatedConnectionPadding ConnectionPaddingPolicy = iota
	// ForceConnectionPadding sends padding even without relay support.
	ForceConnectionPadding
	// ReducedConnectionPadding uses Tor's lower-overhead connection policy.
	ReducedConnectionPadding
	// DisableConnectionPadding disables connection padding.
	DisableConnectionPadding
)

// CircuitPaddingPolicy controls cover traffic inside client circuits.
type CircuitPaddingPolicy uint8

const (
	// StandardCircuitPadding uses all consensus-supported padding machines.
	StandardCircuitPadding CircuitPaddingPolicy = iota
	// ReducedCircuitPadding uses only lower-overhead padding machines.
	ReducedCircuitPadding
	// DisableCircuitPadding disables circuit padding.
	DisableCircuitPadding
)

// ClientIPPolicy controls the address families used to reach relays and the
// preference given to exit addresses. It does not override a numeric bridge.
type ClientIPPolicy uint8

const (
	ClientIPv4Only ClientIPPolicy = iota
	ClientDualStack
	ClientPreferIPv6
	ClientIPv6Only
)

// OnionTrafficPolicy controls which target types the owned SOCKS listener
// accepts. It does not change hosted onion services.
type OnionTrafficPolicy uint8

const (
	AllowOnionAndExitTraffic OnionTrafficPolicy = iota
	OnionTrafficOnly
	RejectOnionTraffic
)

// Config is copied at Start. No raw torrc, arbitrary flags, environment,
// controller handle, or arbitrary SETCONF interface is exposed.
// Zero values select conservative defaults. This driver is a client/onion
// service host, never an exit relay or directory authority.
type Config struct {
	SandboxSlot         string           // empty: DefaultSandboxSlot; use one slot per live Driver
	SandboxTemplate     gobox.TemplateID // empty: DefaultSandboxTemplate
	TorProgram          gobox.ProgramID  // empty: DefaultTorProgram
	StateDirectory      gobox.Path       // empty Rel: disposable state below the temporary work directory
	Sandbox             SandboxMode
	LogLevel            LogLevel
	ForwardTorLogs      bool          // opt-in notice/warn/err text; may still reveal local metadata
	StartupTimeout      time.Duration // default 30s; authenticating, not bootstrap
	CommandTimeout      time.Duration // default 10s
	DialTimeout         time.Duration // default 90s
	ShutdownTimeout     time.Duration // default 10s
	MaxProxyConnections int           // default 256, bounds accepted sessions and dials
	OutboundFailures    OutboundFailurePolicy
	MaxCircuitDirtiness time.Duration // daemon-wide, default 10m
	CircuitBuildTimeout time.Duration // zero leaves Tor's adaptive default
	BandwidthRate       uint64        // bytes/s; zero leaves Tor's default
	BandwidthBurst      uint64
	ConnectionPadding   ConnectionPaddingPolicy
	CircuitPadding      CircuitPaddingPolicy
	ReachableORPorts    []uint16 // empty permits Tor's default relay ports
	MaxPendingCircuits  uint16   // zero leaves Tor's default (32)
	NumCPUs             uint16   // zero lets Tor detect the available CPUs
	ClientIP            ClientIPPolicy
	ClientIPv6          bool // deprecated compatibility alias for ClientDualStack
	OnionTraffic        OnionTrafficPolicy
	EntryNodes          []Fingerprint
	ExitNodes           []Fingerprint
	ExcludeNodes        []Fingerprint
	ExcludeExitNodes    []Fingerprint
	StrictNodes         bool
	UseBridges          bool // requires at least one bridge
	Bridges             []Bridge
	Transports          []TransportConfig
}

type OutboundFailurePolicy uint8

const (
	// RetrySameNetwork rejects failed connections but allows later attempts
	// through the same injected Network. There is never a direct fallback.
	RetrySameNetwork OutboundFailurePolicy = iota
	// LatchOutboundErrors also drops all other sessions after a dial or I/O
	// error. Explicit SetOutbound is then required, even for transient errors.
	LatchOutboundErrors
)

// Fingerprint is validated as exactly 40 hexadecimal characters.
type Fingerprint string

// Transport names a registered client transport. The empty name selects plain TCP.
type Transport string

// Plain selects a bridge without a pluggable transport.
const Plain Transport = ""

// OutboundDial opens a stream on the current outbound attachment. A transport
// can use it during its dial callback. The driver owns the returned streams.
type OutboundDial func(ctx context.Context, network, address string) (net.Conn, error)

// TransportDial completes a transport handshake and returns the stream for Tor.
// It must honor context cancellation. Each invocation owns its argument map.
type TransportDial func(ctx context.Context, address string, args map[string]string, outbound OutboundDial) (net.Conn, error)

// TransportConfig registers one method at Start. Set exactly one of Program and Dial.
type TransportConfig struct {
	Kind    Transport
	Program gobox.ProgramID
	Dial    TransportDial
}

// Bridge describes a numeric bridge endpoint and its optional Tor identity.
type Bridge struct {
	Transport   Transport
	Address     string
	Fingerprint Fingerprint
	Args        map[string]string
	route       string
}

// BridgeConfig replaces all bridges. Methods refer to registrations from Start.
type BridgeConfig struct {
	UseBridges bool
	Bridges    []Bridge
}

type CircuitPolicy uint8

const (
	// SessionCircuits reuses an isolation group for this Network. Tor still
	// chooses/rotates circuits; it does not promise one permanent circuit.
	SessionCircuits CircuitPolicy = iota
	// IsolateEachConnection uses a new isolation group for each Dial/lookup.
	// It forbids sharing a used circuit with other groups, not shared relays.
	IsolateEachConnection
)

// DestinationIsolation selects additional fields that split a Network's
// reusable circuit groups. It has no effect with IsolateEachConnection.
type DestinationIsolation uint8

const (
	IsolateDestinationAddress DestinationIsolation = 1 << iota
	IsolateDestinationPort
)

type NetworkConfig struct {
	Circuits  CircuitPolicy
	Isolation DestinationIsolation
}

type MaxStreamsPolicy uint8

const (
	// KeepRendezvousCircuit rejects excess streams but keeps the circuit.
	KeepRendezvousCircuit MaxStreamsPolicy = iota
	// CloseRendezvousCircuit closes a rendezvous circuit at the stream limit.
	CloseRendezvousCircuit
)

// ServiceConfig creates a v3 service tied to the control connection. Ports are
// reserved at creation. A closed port can be reopened with Listen. KeyName uses
// Dependencies.OnionKeys and makes the identity survive intentional restarts.
type ServiceConfig struct {
	Ports             []uint16
	MaxStreams        uint16 // 0: Tor default (unlimited)
	MaxStreamsPolicy  MaxStreamsPolicy
	KeyName           string
	AuthorizedClients []ClientAuthorizationPublicKey
}

// OutboundState contains attachment state and counters, not a reachability
// guarantee. A closed/latched attachment clears only on SetOutbound.
type OutboundState struct {
	Available  bool
	Generation uint64
	Attempts   uint64
}
