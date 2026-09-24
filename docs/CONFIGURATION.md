# Typed configuration coverage

`Config` is copied at Start. The supported runtime operations are SetOutbound,
transactional replacement of the complete typed bridge set, Network
creation/closure, Service mapping changes, client authorization, and Service
creation/closure. This is a
client/onion-hosting configuration surface; it does not expose every Tor relay,
authority, testing-network or diagnostic option.

## Driver configuration

| Field | Default | Effect |
| --- | --- | --- |
| `TorExecutable` | Required at `Start` | Absolute path to the trusted executable. `direct.FindExecutables` can fill an empty path from the current process `PATH`. |
| `TempRoot` | Adapter temporary root | Parent of a private per-process work directory. |
| `StateDirectory` | Temporary state | Optional private persistent DataDirectory. Never share concurrently between Drivers. |
| `Identity` | Current non-root Linux identity / Windows caller | Explicit nonzero Linux UID/GID; unsupported identity changes fail. |
| `Sandbox` | `DynamicServices` | `LinuxSandbox` opts into Tor seccomp and forbids runtime onion creation; transports are unavailable in this mode. |
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
| `ConnectionPadding` | `NegotiatedConnectionPadding` | Negotiated, forced, reduced, or disabled link padding. |
| `CircuitPadding` | `StandardCircuitPadding` | Standard, reduced, or disabled circuit padding. |
| `ReachableORPorts` | unrestricted | Nonzero unique relay ports mapped to `ReachableORAddresses`. This is not an OS firewall. |
| `MaxPendingCircuits` | Tor default (32) | Optional `MaxClientCircuitsPending` resource limit. |
| `NumCPUs` | Tor detection | Optional worker limit mapped to `NumCPUs`. |
| `ClientIP` | `ClientIPv4Only` | IPv4 only, dual stack, prefer IPv6, or IPv6 only. Numeric bridges still use their configured family. |
| `ClientIPv6` | false | Deprecated compatibility alias for `ClientDualStack`; conflicting explicit policies fail validation. |
| `OnionTraffic` | `AllowOnionAndExitTraffic` | SOCKS target policy: allow both, onion only, or reject onion targets. |
| `EntryNodes`, `ExitNodes`, `ExcludeNodes` | Tor defaults | Slices of validated 40-hex relay fingerprints. Country codes, nicknames and raw expressions are not accepted. |
| `ExcludeExitNodes` | Tor default | Validated fingerprints that cannot be exit relays. |
| `StrictNodes` | false | Corresponding typed Tor client setting. |
| `UseBridges` | false | Bridge mode; must have at least one accepted bridge. |
| `Bridges` | none | Structured numeric endpoint, optional/plain or required/obfs4 fingerprint and typed obfs4 fields. |
| `Transports` | none | Pre-approved managed transports. Only one `Obfs4` registration, an absolute executable path without whitespace or quotes, and no arbitrary arguments are accepted. `direct.FindExecutables` can fill an empty path in an existing registration. A transport can be registered while bridge mode is off for later runtime use. |

`Dependencies.OnionKeys` is optional. It is required when a Service uses a
nonempty `KeyName`. The injected store receives typed private key values and
must protect confidentiality, make a successful Store durable, and implement
create-if-absent behavior after a missing Load. One name can be active only once
in a Driver. Applications must also prevent concurrent use by separate Drivers.

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

Executable discovery is an explicit adapter operation:

```go
cfg, err := direct.FindExecutables(tor.Config{
    // An empty TorExecutable searches PATH for tor.
    Transports: []tor.TransportConfig{{Kind: tor.Obfs4}},
})
if err != nil {
    return err
}
```

The resolver keeps nonempty paths unchanged. For an empty obfs4 path, it first
searches for `lyrebird` and then `obfs4proxy`. It only resolves transports that
are already in `Config.Transports`; finding a program does not enable it. The
result contains absolute paths and is ready for `Start` or for a containment
allowlist. PATH lookup identifies a file by name only. The application remains
responsible for trusting and qualifying the selected binary.

For host applications that accept an explicit fallback to protocol-only
routing, `NewBestEffortSystem` combines executable discovery with automatic
process preparation:

```go
system, cfg, err := direct.NewBestEffortSystem(tor.Config{
    // Explicit executable paths and Identity values take priority.
    Transports: []tor.TransportConfig{{Kind: tor.Obfs4}},
})
if err != nil {
    return err
}
defer system.Close()

report := system.Report()
deps := system.Dependencies(direct.Network(), outgoing, logger)
d, err := tor.Start(ctx, cfg, deps)
```

The constructor makes these decisions in order:

1. It calls `FindExecutables`. Missing required programs are errors.
2. On Linux, it preserves an explicit identity. A non-root caller stays under
   its current identity. A root caller without an explicit identity looks up
   the host `nobody` account and uses its numeric nonzero UID and GID. It does
   not guess numeric IDs when the account is absent.
3. On Linux, it tries the cgroup v2 and nftables adapter with the current cgroup
   as parent. On Windows, strict containment reports `ErrUnsupported` because
   executable-scoped firewall rules do not contain descendant processes.
4. If strict containment is unavailable, it selects the ordinary `System`
   adapter. `Report().ContainmentError` and a warning through the supplied
   logger make this fallback visible.

The first `Dependencies` call writes each preparation decision at debug level.
These messages identify whether Tor and each PT path came from explicit
configuration or `PATH`, show the selected paths, describe the UID/GID and
privilege-drop decision, and identify the selected process adapter. They are
written only once per `BestEffortSystem`. Executable paths and UID/GID values
are local metadata; configure the Logger to suppress debug output when this
metadata must not enter logs. A containment fallback remains a warning.

The automatic adapter does not enable Tor's `LinuxSandbox` mode. That mode
removes capabilities such as managed transports and runtime onion-service
creation, so selecting it without application requirements is not safe.
Configure `LinuxSandbox` explicitly when those capabilities are not needed.
Use `NewContainedSystem` instead of best-effort selection when an external
socket boundary is mandatory. Its initialization error is fail-closed.

All options in the table are available in the supported Tor 0.4.8 baseline.
The generated names are `ConnectionPadding`, `ReducedConnectionPadding`,
`CircuitPadding`, `ReducedCircuitPadding`, `ReachableORAddresses`,
`MaxClientCircuitsPending`, `NumCPUs`, `ClientUseIPv4`, `ClientUseIPv6`,
`ClientPreferIPv6ORPort`, `ExcludeExitNodes`, and documented SOCKS flags. Later
Tor versions can change defaults. The driver writes explicit values where its
zero-value contract must stay stable.

### Client option inventory

| Area | Public decision | Minimum supported Tor | Compatibility behavior |
| --- | --- | --- | --- |
| Padding | Expose connection and circuit policies, including reduced modes. | 0.4.8 | Start fails if Tor rejects the generated fixed mapping. |
| Constrained upstream ports | Expose numeric `ReachableORPorts`. | 0.4.8 | Empty uses Tor's unrestricted default; duplicate or zero ports fail before startup. |
| Relay selection | Expose fingerprint-only entry, exit, general exclusion, and exit exclusion lists. | 0.4.8 | Experimental `MiddleNodes`, onion-layer sets, countries, nicknames, and address expressions stay unavailable. |
| Bootstrap limits | Keep consensus delays and retry schedules managed by Tor. | 0.4.8 | `StartupTimeout` covers authentication and `WaitReady` covers usable bootstrap without changing network timing. |
| Resource limits | Expose bandwidth, pending client circuits, CPU workers, and parent-proxy sessions. | 0.4.8 | Values are locally bounded where Tor specifies a bound; other semantic rejection makes Start fail. |
| IP preferences | Expose IPv4-only, dual-stack, prefer-IPv6, and IPv6-only policies. | 0.4.8 | Numeric bridges and proxies keep their explicit family, as Tor specifies. |
| Onion client settings | Expose SOCKS onion-only/reject flags and typed v3 authorization commands. | 0.4.8 | Policies apply to all Networks in one Driver; use another Driver for a different policy. |

## Linux process containment

Containment is a dependency choice, not a Tor option. The normal `direct.System`
adapter enforces the proxy route at the protocol level. Use the optional Linux
adapter when the host can provide cgroup v2 and nftables control:

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
The caller must be able to create a child cgroup, but the Tor identity must not
be able to write the parent `cgroup.procs` file. A root caller must select a
non-root Tor identity. Setup checks parent migration permissions again for that
configured identity before launch. A delegation that permits parent migration
is rejected because the child could leave the filtered cgroup.
Cleanup removes nftables rules only after the cgroup is confirmed empty.

On Windows, `NewContainedSystem` fails with `ErrUnsupported`. Windows Firewall
program rules follow executable paths rather than a complete Job Object process
tree. A descendant can run another image path, so these rules are not a strict
containment boundary. Use an external sandbox that gives Tor and every
descendant one enforceable network identity. `BestEffortSystem` selects the
ordinary `System` adapter and reports this fallback.

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
never quietly switches to public guards. Bridge lines supplied without
UseBridges also fail. A transport without a bridge is a standby registration.

Only obfs4 is an approved transport protocol. Its executable
path must be one unquoted Tor `exec` token, so paths with whitespace or quote
characters are rejected. The executable must honor authenticated SOCKS5 through
TOR_PT_PROXY. Neither a filename nor an enum can attest that an arbitrary
executable does so; certify exact binary versions using the PT integration test
and packet-level checks before deployment.

`SetBridges` accepts the same typed bridges and transports at runtime. It first
sets `DisableNetwork=1`. It then sends one all-or-nothing `SETCONF` for
`UseBridges`, all `Bridge` values, and all `ClientTransportPlugin` values. Tor
0.4.8 supports this control operation. The driver enables networking only after
Tor accepts the complete set. If enablement fails, the driver tries to restore
the old complete set. After networking is disabled, every later error path stays
network-disabled. If Tor rejects the initial disable while changing from direct
guards to bridges, the driver shuts down. Thus, a failed request to enter bridge
mode cannot continue through direct guards. Call `SetBridges` again with a valid
complete configuration to recover from a disabled but active driver.
`UseBridges: false` is an explicit request to return to public guards.
After Tor re-enables networking, the driver queries and publishes the new
acknowledged auto SOCKS endpoint before `SetBridges` returns.

Runtime configuration cannot authorize a new executable. Each managed
transport in `BridgeConfig` must exactly match a registration in the initial
`Config.Transports`. This lets the generated startup configuration select
Tor's `NoExec` safeguard when no transport will ever be needed. To start with
direct guards and change to obfs4 later, put the trusted obfs4 registration in
`Config.Transports` and leave `Config.UseBridges` false.

## Networks and services

| API | Typed configuration | Operations |
| --- | --- | --- |
| `NewNetwork` | `NetworkConfig{Circuits, Isolation}` | Reusable or per-connection groups, optional destination-address and destination-port isolation, TCP dialing, Tor lookups, and offline LookupPort. |
| `NewService` | `ServiceConfig{Ports, MaxStreams, MaxStreamsPolicy, KeyName, AuthorizedClients}` | 1–128 distinct nonzero virtual ports; Listen/ListenTCP, acknowledged RemovePort/reopen, publication wait/events, immediate Close, and Drain. |

There is no per-Network upstream override: the Driver's outgoing attachment is
shared by all its circuits and services. Use another Driver for different
daemon-wide bridge, relay-selection, state or timeout policies. A Service is
listen-only; create a separate Network from its Driver if it also needs client
connections.

The SOCKS listener always enables `IsolateSOCKSAuth`. A Network derives its
authentication token from the selected destination fields. This gives the Tor
circuit split without mutable listeners. `IsolateDestinationAddress`
normalizes DNS names to lower case. `IsolateDestinationPort` separates target
ports. `IsolateEachConnection` is stronger and makes both fields redundant.

Tor 0.4.8 has one daemon-wide `MaxCircuitDirtiness` value. It cannot give
different reuse ages to authentication groups on one SOCKS listener. Use
separate Drivers when reuse ages must differ. The driver also does not expose
literal circuit pinning. A safe pinning API must own STREAM events, attach
failures, circuit closure, and cancellation without racing Tor's normal stream
attachment. That is a separate controller feature, not a `NetworkConfig` flag.

## Intentionally unavailable

Raw torrc, `%include`, extra argv, environment injection, arbitrary SETCONF,
unmanaged transports, caller-chosen control/SOCKS ports, direct proxy bypass,
relay/exit operation, UDP forwarding, authenticated client identity metadata on
accepted onion streams, stream-to-circuit attachment, country-selection
expressions, experimental middle-node selection, and unqualified transports are
not exposed.

## Controller and transport evaluation

The private controller stays in production. Its parser is bounded, closes on
ambiguous cancellation, injects only the existing connection, and has a small
differential reply corpus against Bine. A Bine adapter adds a second command and
event model without removing the lifecycle integration work. It would increase
maintenance cost without increasing current coverage.

Obfs4 remains the only transport. Approved transports require a named type, a
fixed argument model, authenticated `TOR_PT_PROXY` qualification, failure and
replacement tests, and IPv4, IPv6, and DNS denial evidence. A protocol name
alone does not approve an executable.
