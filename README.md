# tor-driver

A Go library that owns a Tor **client daemon**, exposes closable
`gonnect.Network` instances, hosts v3 onion services, and sends Tor's
external connections through a replaceable, explicitly supplied
`gonnect.Network`.

> [!WARNING]
> This library is experimental and has not been audited yet. Do not use it in
> production or for security-critical applications.

## Included

- Foreground Tor lifecycle, temporary authenticated control connection,
  SAFECOOKIE server verification, ownership, graceful shutdown and forced cleanup.
- An authenticated localhost SOCKS5 CONNECT proxy with a fixed address for the
  daemon's lifetime. Its only external dial path is the injected outgoing network.
- Runtime `SetOutbound`, including `nil`, cancellation of old dials, closure of
  both sides of old sessions, and optional network close/down subscriptions.
- Independent Tor networks with reusable or per-connection SOCKS isolation groups.
- TCP dialing and Tor DNS resolution using `socksgo`; no loopback or local DNS
  fallback. Unsupported `gonnect` operations reject requests.
- Runtime v3 onion services implementing a listen-only `gonnect.Network`, with
  typed publication events, optional injected key persistence, protected-service
  client authorization, mutable virtual ports, and explicit draining.
- Typed configuration for padding, IP and onion policies, resource limits,
  relay selection, state, logging, bridges and obfs4.
  Unsupported transport registrations fail; unsupported bridge transports are
  ignored. Empty bridge mode fails instead of using public guards.
- Injected filesystem, process, clock, randomness, local network, outgoing
  network and the requested Logger interface. Native adapters live in `direct`.
- Linux UID/GID transition, ambient-capability removal, pidfd/cgroup-assisted
  cleanup, race-resistant file operations, and an optional cgroup/nftables
  containment adapter. The direct package can select available protections and
  report any fallback. Windows
  uses atomic private directory ACLs and nested Job cleanup. Strict Windows
  network containment is unavailable because executable-scoped firewall rules
  do not contain descendant processes. See the platform limits in the
  architecture document.

## Build and run

Install Go 1.25.5 or newer and a Tor build with v3 onion services and SAFECOOKIE
(target baseline: Tor 0.4.8 or newer). Tor and obfs4 binaries are supplied by the
application; the library does not download them. `direct.FindExecutables` and
`direct.NewBestEffortSystem` can find missing paths in the current process
`PATH`. Explicit paths have priority. Dependencies are pinned in `go.mod` to
gonnect v0.47.0 and socksgo v0.4.12.

```sh
just check
just example
```

The Nix development shell supplies `just` and the other development tools. You
can also run the underlying Go commands directly; see
[TESTING.md](docs/TESTING.md).

The example starts two independent daemons. One serves HTTP on an onion service;
the other fetches it through a Tor `Network`. It waits for bootstrap and a
confirmed descriptor upload before the client fetches the descriptor. It
contacts the public Tor network and can take several minutes.

On Windows, put Tor in `PATH` or use the executable's absolute path:

```powershell
go mod tidy
go test -timeout 2m ./...
go run ./examples/onion-http -tor 'C:\Tor\tor.exe'
```

The examples use `direct.NewBestEffortSystem`. It tries strict OS containment
and logs a warning if only the ordinary process adapter is available. On Linux,
run as an ordinary user when possible. A root caller automatically selects the
host `nobody` account. The `-uid` and `-gid` options override that decision with
an explicit non-root identity. The selected identity needs access to each
executable and to the parent directories of configured state/temp paths. Use a
separate `StateDirectory` per daemon if guard state must survive restarts. The
main example uses disposable state for both processes.

The repository includes `go.sum`. Run `go mod tidy -diff` to check module-file
consistency without changing the files.

## Public API

The concrete types implement the relevant `gonnect` interfaces and also expose
explicit lifecycle methods:

```go
func Start(context.Context, Config, Dependencies) (*Driver, error)

func (*Driver) WaitReady(context.Context) error
func (*Driver) SubscribeEvents(int) (<-chan DriverEvent, func(), error)
func (*Driver) SetOutbound(gonnect.Network) error
func (*Driver) SetBridges(context.Context, BridgeConfig) error
func (*Driver) OutboundState() OutboundState
func (*Driver) NewNetwork(NetworkConfig) (*Network, error)
func (*Driver) NewService(context.Context, ServiceConfig) (*Service, error)
func (*Driver) GenerateClientAuthorization(string) (ClientAuthorization, error)
func (*Driver) AddClientAuthorization(context.Context, string, ClientAuthorization) error
func (*Driver) RemoveClientAuthorization(context.Context, string) error
func (*Driver) Done() <-chan struct{}
func (*Driver) Err() error
func (*Driver) Close() error

// Network: gonnect.Network + io.Closer + gonnect.CloserSubscriber
// Service: gonnect.Network + io.Closer + gonnect.CloserSubscriber
func (*Service) Address() string
func (*Service) WaitPublished(context.Context) error
func (*Service) SubscribeEvents(int) (<-chan ServiceEvent, func(), error)
func (*Service) RemovePort(context.Context, uint16) error
func (*Service) Drain(context.Context) error
```

`Start` returns a typed `*StartupError` with a bounded `StartupStage`. Driver
event subscriptions can also receive `OutboundEvent` and `ShutdownEvent`.
These diagnostics contain categories, generations, and latch state. They do
not contain destinations, backend error text, credentials, bridges, executable
paths, or private keys. `Close` still returns the complete joined cleanup error
to its direct caller.

For example, inside a function returning `error`:

```go
system, cfg, err := direct.NewBestEffortSystem(tor.Config{
    TorExecutable: torPath, // empty searches PATH
})
if err != nil {
    return err
}
defer system.Close()

deps := system.Dependencies(
    direct.Network(), // fixed local networking; reaches the owned child
    outgoing,         // your gonnect.Network; nil is also valid
    logger,           // your Logger or tor.NopLogger{}
)
d, err := tor.Start(ctx, cfg, deps)
if err != nil {
    return err
}
defer d.Close()

n, err := d.NewNetwork(tor.NetworkConfig{Circuits: tor.SessionCircuits})
if err != nil {
    return err
}
defer n.Close()

transport := &http.Transport{DialContext: n.Dial, Proxy: nil}
defer transport.CloseIdleConnections()
client := &http.Client{Transport: transport, Timeout: time.Minute}
_ = client // Use for HTTP requests after d.WaitReady(ctx).

if err := d.SetOutbound(nil); err != nil { // disconnects old sessions
    return err
}
if err := d.SetOutbound(replacement); err != nil {
    return err // a failed replacement leaves outgoing traffic blocked
}
```

Use `import tor "github.com/asciimoth/tor-driver"` and
`"github.com/asciimoth/tor-driver/direct"`. The full runnable example includes
all imports and error handling.

Create a service on the *serving* driver:

```go
service, err := d.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80}})
if err != nil {
    return err
}
defer service.Close()
listener, err := service.Listen(ctx, "tcp", ":80")
if err != nil {
    return err
}
if err := service.WaitPublished(ctx); err != nil {
    return err
}
// Pass listener to http.Server.Serve. Clients dial service.Address()+":80".
```

The service object is the returned listening `gonnect.Network`. Virtual ports
must be reserved at creation. Closing a returned listener removes only that
port after Tor acknowledges the changed mapping. `Listen` can then reopen the
port with a new backing endpoint. `Service.Close` closes accepted connections;
`Service.Drain` waits for them to close. Creating a service acknowledges Tor
registration. `WaitPublished` separately waits for a confirmed descriptor
upload.

Set `ServiceConfig.KeyName` and provide `Dependencies.OnionKeys` to keep an
identity across intentional restarts. The key store receives a typed
`OnionServiceKey`, which is Tor's 64-byte expanded Ed25519 key. It is not a Go
Ed25519 seed. The package also has typed X25519 client-authorization keys for
protected services. Tor confirms that an accepted stream reached a protected
service, but it does not report which authorized key the client used. The
accepted connection therefore has no client identity metadata.

## Semantics to rely on

| Choice or event | Behavior |
| --- | --- |
| `SessionCircuits` | One random SOCKS isolation group per Network; Tor can reuse eligible circuits and still rotates/replaces them. |
| `IsolateEachConnection` | A fresh group for each Dial/lookup; no promise of a different exit IP or fresh relay set. HTTP connection pooling can reuse an existing stream. |
| `SetOutbound(nil)` | All old proxy sessions close; subsequent requests fail at the same proxy. Tor remains owned and running. |
| Replace outgoing network | Cancel old dials and close old sessions before installing the new attachment. Returned late connections are closed. |
| Replace bridges | Disable Tor networking, atomically replace the complete typed bridge set, then re-enable. Any rejection or rollback failure stays network-disabled. |
| Backend reports close/down | Block that attachment and close its sessions. Reattach explicitly with `SetOutbound`. |
| Ordinary dial failure | Default: reject this connection; later attempts can only use the same injected Network. |
| `LatchOutboundErrors` | Also close the attachment's other sessions on dial/I/O errors; explicit reattachment is required. |
| Network without close notifications | Existing socket closure and Dial errors are observable; silent closure of the abstract Network itself cannot be detected magically. |
| Driver/control/process failure | Driver becomes terminal; dependent networks/services close. There is no automatic daemon restart. |
| Driver event subscription | Reports typed bootstrap, transport, and terminal state. Raw Tor messages, executable paths, bridge addresses, and credentials are not exposed. |
| Outgoing diagnostics | Reports typed attachment, closure, dial, and stream failure categories. A bounded subscription retains only recent events. |
| Shutdown diagnostics | Reports the cleanup stage that failed; `Close` returns the complete error. |
| Service publication wait | Completes after an `HS_DESC UPLOADED` event and is cancellable. A mapping change returns it to pending. |
| Listener close | Removes only its virtual port after an acknowledged DEL/ADD update; accepted connections remain open. |
| `Service.Drain` | Withdraws all mappings, closes listeners, and waits for accepted connections. Context cancellation forces connection closure. |

The supplied dependencies remain caller-owned. `BestEffortSystem` and
`ContainedSystem` are caller-owned too; close them if Driver does not take them
through process startup. Avoid cyclic outgoing-network graphs. Passing a Network
from this same Driver directly back into `SetOutbound` is rejected; indirect
cycles are the application's responsibility.

## Documentation

- [Operational examples](examples/README.md)
- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Typed configuration coverage](docs/CONFIGURATION.md)
- [Tests, e2e setup and validation status](docs/TESTING.md)
- [Support and release policy](docs/SUPPORT.md)

Tor supports `Socks5Proxy` for its relay connections. Managed transports receive
`TOR_PT_PROXY`; the transport must implement that contract. This project permits
obfs4 only and never accepts an arbitrary transport command. The ordinary direct
adapter supplies protocol routing, not a kernel firewall. On Linux, applications
that can provide a cgroup parent protected from the child identity, plus
nftables privileges, can select `direct.NewContainedSystem` for an
external-socket denial boundary.
See the [Tor proxy specification](https://spec.torproject.org/proposals/232-pluggable-transports-through-proxy.html)
and [PT environment contract](https://spec.torproject.org/pt-spec/configuration-environment.html).

## Alternatives

tor-driver is for Go applications that must own a client-mode Tor process and
route its external connections through an injected `gonnect.Network`. It gives
the application typed lifecycle, routing, isolation, onion-service, and
containment APIs. It intentionally does not expose a general Tor controller or
arbitrary torrc settings.

- [Bine](https://github.com/cretz/bine) is a Go library with a broader Tor
  controller, `net.Conn` and `net.Listen` APIs, and optional static Tor
  embedding. Use tor-driver when you need its injected network boundary,
  explicit dependency model, typed configuration, or process containment.
- [Stem](https://github.com/torproject/stem) is a Python library for scripting
  the Tor control protocol. It is a better fit when a Python application needs
  general control-protocol access. tor-driver instead supplies a constrained,
  higher-level Go API for an owned client daemon.
- [txtorcon](https://github.com/meejah/txtorcon) is a Python and Twisted library
  that can start or connect to Tor, track its state, change its configuration,
  build circuits, and create onion services. tor-driver does not expose relay
  state or manual circuit construction; it integrates Tor with Go through
  closable `gonnect.Network` values.
- [Orc](https://github.com/sycamoreone/orc) is a Go control-protocol library
  with a partial, low-level API. tor-driver owns the process and supplies the
  higher-level lifecycle, routing, and onion-service behavior as one package.
