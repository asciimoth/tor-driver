// Package tordriver owns a Tor client process and exposes isolated gonnect
// networks and v3 onion services. It never supplies a default egress.
package tordriver

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"time"

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

// FileSystem paths must be visible to the process returned by Processes.Start.
// PrivateDir must reject symlinks and make the directory private to its owner.
// With an Identity, the controller must retain permission to read Tor's cookie.
// ReadFile must enforce limit before allocating unbounded storage.
type FileSystem interface {
	TempDir(parent, pattern string) (string, error)
	PrivateDir(path string, owner *Identity) error
	WriteFile(path string, data []byte, mode fs.FileMode, owner *Identity) error
	ReadFile(path string, limit int64) ([]byte, error)
	RemoveAll(path string) error
}

// Identity requests a Linux UID/GID transition before executing Tor. Both must
// be nonzero. Unsupported platforms/adapters must return an error.
type Identity struct{ UID, GID uint32 }

// Launch is a trusted adapter boundary, not a public Tor configuration escape
// hatch. Driver alone builds Args. Implementations must not use a shell, merge
// a user's torrc, or inherit environment variables that inject executable code.
type Launch struct {
	Executable     string
	Args           []string
	Directory      string
	Identity       *Identity
	Stdout, Stderr io.Writer
}

// Process.Wait is called once. Kill must terminate the process and owned PT
// children. Release releases process-tree bookkeeping after Wait (e.g. a Job).
type Process interface {
	Wait() error
	Kill() error
	Release() error
}

type Processes interface {
	Start(context.Context, Launch) (Process, error)
	PID() int
	Platform() string
}

// Clock abstracts wall time and timers used by the driver. Go's scheduler and
// synchronization primitives are intentionally not replaced.
type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
	Timeout(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

// Dependencies are borrowed; Driver does not close the supplied networks,
// logger, entropy reader, filesystem or process adapter. LocalNetwork must
// reach the child process's numeric loopback endpoints. A purely in-memory
// Network needs a matching virtual Process adapter.
type Dependencies struct {
	FS           FileSystem
	Processes    Processes
	Clock        Clock
	Random       io.Reader
	Logger       Logger
	LocalNetwork gonnect.Network
	Outbound     gonnect.Network // nil starts with blocked outbound traffic
	OnionKeys    OnionKeyStore   // required only by a named persistent service
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
	TorExecutable       string // absolute path required
	TempRoot            string // empty: adapter's private temporary location
	StateDirectory      string // empty: disposable state; nonempty: caller-owned persistent guard state
	Identity            *Identity
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
	UseBridges          bool // if all bridges are ignored, Start fails; no fallback to guards
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
type Transport string

const (
	Plain Transport = ""
	Obfs4 Transport = "obfs4"
)

// TransportConfig registers a library-approved managed transport implementation.
// Only Obfs4 is accepted. Executable is trusted code, not verified by its name.
// It must be an absolute path without whitespace or quote characters. There is
// deliberately no argument slice or generic transport-options map.
type TransportConfig struct {
	Kind       Transport
	Executable string
}

type IATMode uint8

const (
	IATDisabled IATMode = iota
	IATEnabled
	IATParanoid
)

type Bridge struct {
	Transport        Transport
	Address          string      // numeric IP:port; hostnames are rejected
	Fingerprint      Fingerprint // required for obfs4, optional for plain bridges
	Obfs4Certificate string      // base64 encoding of exactly 52 bytes
	IAT              IATMode
}

// BridgeConfig is the complete runtime bridge configuration. UseBridges needs
// at least one supported bridge. Managed transports must be pre-approved in
// the initial Config. A false value explicitly returns to guards.
type BridgeConfig struct {
	UseBridges bool
	Bridges    []Bridge
	Transports []TransportConfig
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
