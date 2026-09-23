# tor-driver

A Go starter library that owns a Tor **client daemon**, exposes closable
`gonnect.Network` instances, hosts ephemeral v3 onion services, and sends Tor's
external connections through a replaceable, explicitly supplied
`gonnect.Network`.

**Validation status:** formatting, module checks, vet, unit tests with the race
detector, injected lifecycle and concurrency tests, fuzz smoke tests, lint, typo
checks, a Windows cross-build, and the offline real-Tor test pass on Linux.
The Linux two-daemon public onion test also passes. Hosted CI now defines pinned
Linux and Windows runtime gates, an automatic network-disabled private Tor and
obfs4 Docker gate, and manual public Tor gates. A workflow definition is not a
recorded successful run; see
[TESTING.md](docs/TESTING.md) for the version matrix and remaining gates. This
project is a starting point, not an audited release.

The module path is `github.com/asciimoth/tor-driver`.

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
- Runtime ephemeral v3 onion services implementing a listen-only
  `gonnect.Network`; backing listeners and accepted connections belong to Driver.
- Typed configuration for client settings, state, logging, bridges and obfs4.
  Unsupported transport registrations fail; unsupported bridge transports are
  ignored. Empty bridge mode fails instead of using public guards.
- Injected filesystem, process, clock, randomness, local network, outgoing
  network and the requested Logger interface. Native adapters live in `direct`.
- Linux UID/GID transition, pidfd/cgroup-assisted cleanup, race-resistant file
  operations, and an optional cgroup/nftables containment adapter. Windows uses
  directory ACLs and Job Object cleanup. See the platform limits in the
  architecture document.

## Build and run

Install Go 1.25.5 or newer and a Tor build with v3 onion services and SAFECOOKIE
(target baseline: Tor 0.4.8 or newer). Tor and obfs4 binaries are supplied by the
application; the library does not download them. Dependencies are pinned in
`go.mod` to gonnect v0.47.0 and socksgo v0.4.12.

```sh
just check
just example -tor /usr/bin/tor
```

The Nix development shell supplies `just` and the other development tools. You
can also run the underlying Go commands directly; see
[TESTING.md](docs/TESTING.md).

The example starts two independent daemons. One serves HTTP on an onion service;
the other fetches it through a Tor `Network`. It waits for bootstrap and retries
while the onion descriptor propagates. It contacts the public Tor network and
can take several minutes.

On Windows, use the executable's absolute path:

```powershell
go mod tidy
go test -timeout 2m ./...
go run ./examples/onion-http -tor 'C:\Tor\tor.exe'
```

On Linux, run as an ordinary user. A root caller must use `-uid` and `-gid` with
an existing non-root identity; that identity needs access to the executable and
the parent directories of any configured state/temp paths. Use a separate
`StateDirectory` per daemon if you want guard state to survive restarts. The
example uses disposable state for both processes.

The repository includes `go.sum`. Run `go mod tidy -diff` to check module-file
consistency without changing the files.

## Public API

The concrete types implement the relevant `gonnect` interfaces and also expose
explicit lifecycle methods:

```go
func Start(context.Context, Config, Dependencies) (*Driver, error)

func (*Driver) WaitReady(context.Context) error
func (*Driver) SetOutbound(gonnect.Network) error
func (*Driver) OutboundState() OutboundState
func (*Driver) NewNetwork(NetworkConfig) (*Network, error)
func (*Driver) NewService(context.Context, ServiceConfig) (*Service, error)
func (*Driver) Done() <-chan struct{}
func (*Driver) Err() error
func (*Driver) Close() error

// Network: gonnect.Network + io.Closer + gonnect.CloserSubscriber
// Service: gonnect.Network + io.Closer
func (*Service) Address() string
```

For example, inside a function returning `error`:

```go
deps := direct.Dependencies(
    direct.Network(), // fixed local networking; reaches the owned child
    outgoing,         // your gonnect.Network; nil is also valid
    logger,           // your Logger or tor.NopLogger{}
)
d, err := tor.Start(ctx, tor.Config{TorExecutable: torPath}, deps)
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
// Pass listener to http.Server.Serve. Clients dial service.Address()+":80".
```

The service object is the returned listening `gonnect.Network`. Virtual ports
must be reserved at creation and each can be claimed once. In this starter,
closing **any** returned listener withdraws the entire service, including its
other ports. Creating a service acknowledges Tor registration, not publication.

## Semantics to rely on

| Choice or event | Behavior |
| --- | --- |
| `SessionCircuits` | One random SOCKS isolation group per Network; Tor can reuse eligible circuits and still rotates/replaces them. |
| `IsolateEachConnection` | A fresh group for each Dial/lookup; no promise of a different exit IP or fresh relay set. HTTP connection pooling can reuse an existing stream. |
| `SetOutbound(nil)` | All old proxy sessions close; subsequent requests fail at the same proxy. Tor remains owned and running. |
| Replace outgoing network | Cancel old dials and close old sessions before installing the new attachment. Returned late connections are closed. |
| Backend reports close/down | Block that attachment and close its sessions. Reattach explicitly with `SetOutbound`. |
| Ordinary dial failure | Default: reject this connection; later attempts can only use the same injected Network. |
| `LatchOutboundErrors` | Also close the attachment's other sessions on dial/I/O errors; explicit reattachment is required. |
| Network without close notifications | Existing socket closure and Dial errors are observable; silent closure of the abstract Network itself cannot be detected magically. |
| Driver/control/process failure | Driver becomes terminal; dependent networks/services close. There is no automatic daemon restart. |

The supplied dependencies remain caller-owned. Avoid cyclic outgoing-network
graphs. Passing a Network from this same Driver directly back into `SetOutbound`
is rejected; indirect cycles are the application's responsibility.

## Design and further work

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Typed configuration coverage](docs/CONFIGURATION.md)
- [Tests, e2e setup and validation status](docs/TESTING.md)
- [Implementation roadmap](docs/ROADMAP.md)

Tor supports `Socks5Proxy` for its relay connections. Managed transports receive
`TOR_PT_PROXY`; the transport must implement that contract. This project permits
obfs4 only and never accepts an arbitrary transport command. The ordinary direct
adapter supplies protocol routing, not a kernel firewall. On Linux, applications
that can delegate cgroup v2 and nftables privileges can select
`direct.NewContainedSystem` for an external-socket denial boundary.
See the [Tor proxy specification](https://spec.torproject.org/proposals/232-pluggable-transports-through-proxy.html)
and [PT environment contract](https://spec.torproject.org/pt-spec/configuration-environment.html).
