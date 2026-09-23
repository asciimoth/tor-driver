# Typed configuration coverage

Configuration is immutable after Start. The supported runtime operations are
SetOutbound, Network creation/closure, and Service creation/closure. This is a
client/onion-hosting configuration surface; it does not expose every Tor relay,
authority, testing-network or diagnostic option.

## Driver configuration

| Field | Default | Effect |
| --- | --- | --- |
| `TorExecutable` | Required | Absolute path to the trusted executable; no shell or PATH lookup in Driver. |
| `TempRoot` | Adapter temporary root | Parent of a private per-process work directory. |
| `StateDirectory` | Temporary state | Optional private persistent DataDirectory. Never share concurrently between Drivers. |
| `Identity` | Current non-root Linux identity / Windows caller | Explicit nonzero Linux UID/GID; unsupported identity changes fail. |
| `Sandbox` | `DynamicServices` | `LinuxSandbox` opts into Tor seccomp and forbids runtime onion creation; transports unavailable in this starter mode. |
| `LogLevel` | `LogNotice` | Typed notice/warn/error Tor output level. |
| `ForwardTorLogs` | false | Opt-in forwarding of bounded daemon output to Logger. |
| `StartupTimeout` | 30 seconds | Bounds local initialization and control authentication, not bootstrap. |
| `CommandTimeout` | 10 seconds | Maximum controller operation time; cancellation after transmission terminates control ownership. |
| `DialTimeout` | 90 seconds | Maximum SOCKS handshake, Tor lookup and outgoing connection establishment time; established streams have no imposed lifetime. |
| `ShutdownTimeout` | 10 seconds | Per-stage shutdown/reaping wait, not a single total Close budget. |
| `MaxProxyConnections` | 256 | Bounds accepted proxy sessions, including pending handshakes/dials; valid range 1–65536. |
| `OutboundFailures` | `RetrySameNetwork` | `LatchOutboundErrors` requires explicit SetOutbound after non-cancellation network errors. Neither policy has another dialer. |
| `MaxCircuitDirtiness` | 10 minutes | Daemon-wide circuit reuse age. Not a pinning guarantee. |
| `CircuitBuildTimeout` | Tor adaptive default | Optional explicit build timeout. |
| `BandwidthRate`, `BandwidthBurst` | Tor defaults | Bytes/second and burst bytes; supply both, burst at least rate. |
| `ClientIPv6` | false | Enables IPv6 on Tor's client-to-relay side. Separate from asking an exit for an IPv6 target. |
| `EntryNodes`, `ExitNodes`, `ExcludeNodes` | Tor defaults | Slices of validated 40-hex relay fingerprints. Country codes, nicknames and raw expressions are not accepted. |
| `StrictNodes` | false | Corresponding typed Tor client setting. |
| `UseBridges` | false | Bridge mode; must have at least one accepted bridge. |
| `Bridges` | none | Structured numeric endpoint, optional/plain or required/obfs4 fingerprint and typed obfs4 fields. |
| `Transports` | none | Only `Obfs4`, one registration, absolute executable path without whitespace or quotes, no arbitrary arguments. |

Timeouts are bounded to 1 second through 24 hours; zero selects the documented
default. An explicit circuit-build timeout follows the same bounds. Tor can
impose additional semantic limits; a generated configuration it rejects makes
Start fail. Durations passed to Tor are expressed in whole seconds.

The mandatory generated values are internal: the upstream proxy and credentials,
loopback SOCKS/control ports, cookie path/authentication, ownership, client-only
mode, safe logs, foreground operation and compatible self-restrictions. Public
configuration cannot override them. The trusted Process adapter receives the
generated Launch arguments because it must execute them; it is not an untrusted
configuration input.

## Linux process containment

Containment is a dependency choice, not a Tor option. The normal `direct.System`
adapter enforces the proxy route at the protocol level. Use the optional Linux
adapter when the host can delegate cgroup v2 and nftables control:

```go
contained, err := direct.NewContainedSystem(direct.LinuxContainmentConfig{
    CgroupParent: "/sys/fs/cgroup/my-delegated-scope", // empty: current cgroup
})
if err != nil {
    return err
}
defer contained.Close() // required if Driver never starts

deps := contained.Dependencies(direct.Network(), outgoing, logger)
d, err := tor.Start(ctx, cfg, deps)
```

The adapter is single-use and fails if it cannot install the boundary. It does
not fall back to protocol-only routing. Its nftables rules permit loopback for
dynamic control, SOCKS, onion backing, proxy, and PT endpoints. They reject and
count external IPv4 and IPv6 packets from Tor and inherited PT children. The
parent proxy is not in the filtered cgroup and continues to use only `outgoing`.

## Bridges and transports

```go
cfg.UseBridges = true
cfg.Transports = []tor.TransportConfig{{
    Kind: tor.Obfs4,
    Executable: "/usr/bin/obfs4proxy",
}}
cfg.Bridges = []tor.Bridge{{
    Transport: tor.Obfs4,
    Address: bridgeAddress,             // numeric IP:port
    Fingerprint: tor.Fingerprint(fp),   // 40 hex characters
    Obfs4Certificate: cert,             // base64 for 52 bytes
    IAT: tor.IATDisabled,
}}
```

The IAT enum also supports `IATEnabled` and `IATParanoid`. Plain bridges use
`Transport: tor.Plain`, a numeric address, an optional fingerprint and no obfs4
fields. No raw bridge-line parser is exposed.

Unknown transport registrations always return ErrUnsupportedTransport. Unknown
bridge transports are ignored without interpreting their other fields, with an
index-only log message. Malformed fields for a *supported* bridge fail validation.
If all bridge entries were ignored, UseBridges still fails; the implementation
never quietly switches to public guards. Supported bridges or registered
transports supplied without UseBridges also fail.

Only obfs4 is an approved transport protocol in this starter. Its executable
path must be one unquoted Tor `exec` token, so paths with whitespace or quote
characters are rejected. The executable must honor authenticated SOCKS5 through
TOR_PT_PROXY. Neither a filename nor an enum can attest that an arbitrary
executable does so; certify exact binary versions using the PT integration test
and packet-level checks before deployment.

## Networks and services

| API | Typed configuration | Operations |
| --- | --- | --- |
| `NewNetwork` | `NetworkConfig{Circuits: SessionCircuits}` or `IsolateEachConnection` | TCP Dial/DialTCP; LookupIP/LookupHost/LookupIPAddr/LookupNetIP and LookupAddr via Tor; offline LookupPort. |
| `NewService` | `ServiceConfig{Ports: []uint16{...}, MaxStreams: ...}` | 1–128 distinct nonzero virtual ports; Listen/ListenTCP on the service's own onion hostname or `:port`. |

There is no per-Network upstream override: the Driver's outgoing attachment is
shared by all its circuits and services. Use another Driver for different
daemon-wide bridge, relay-selection, state or timeout policies. A Service is
listen-only; create a separate Network from its Driver if it also needs client
connections.

## Intentionally unavailable

Raw torrc, `%include`, extra argv, environment injection, arbitrary SETCONF,
unmanaged transports, caller-chosen control/SOCKS ports, direct proxy bypass,
relay/exit operation, UDP forwarding, persistent onion keys, client authorization,
stream-to-circuit attachment, country-selection expressions, and runtime bridge
reconfiguration are not exposed. See ROADMAP.md for typed extensions.
