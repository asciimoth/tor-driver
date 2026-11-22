# Configuration

## Sandbox selection

| Field | Default | Meaning |
| --- | --- | --- |
| `SandboxSlot` | `tor` | Owner-local sandbox instance slot. |
| `SandboxTemplate` | `tor` | Host-approved sandbox template. |
| `TorProgram` | `tor` | Host-approved Tor program. |
| `StateDirectory` | temporary `state` | Portable sandbox path. Use `gobox.Persistent` to keep state. |

All identifiers must pass `gobox.ValidateName`. `StateDirectory` must pass
`gobox.ValidatePath`. The host maps logical program IDs to executable images;
the library does not accept executable paths.

`Dependencies.Sandboxes` is required. The clock, random source, and logger are
also required. `Outbound` can be nil. `OnionKeys` is required only for a named
persistent onion service.

## Bridges and client transports

Register each method once in `Config.Transports`. Set `Dial` for a Go
implementation or `Program` for a sandbox-approved managed program.
Use a C identifier for the method name. An empty bridge transport selects
plain TCP. Each bridge has a numeric address and an optional 40-digit hex
fingerprint. Tor verifies the supplied fingerprint.

```go
cfg.Transports = []tor.TransportConfig{
    {Kind: "sample", Dial: sampleDial},
    {Kind: "obfs4", Program: "lyrebird"},
}
cfg.UseBridges = true
cfg.Bridges = []tor.Bridge{
    {Transport: "sample", Address: "192.0.2.10:443",
        Args: map[string]string{"mode": "first"}},
    {Address: "192.0.2.12:9001"},
}
```

A `tor.TransportDial` receives a context, the real bridge address, a private
copy of its arguments, and an outbound dial function. Use that function for
network access. Complete the handshake before returning the stream. Honor
context cancellation during the handshake. The driver closes the stream
and its outbound connections when the session ends or the attachment closes.

Tor rejects external SOCKS transport plugins when its global upstream proxy
is set. For a Go method, the driver gives Tor a logical bridge address on the
authenticated proxy. The address selects the transport and its arguments.
These arguments stay in the application process. The logical address retains
the bridge port and address family. In bridge mode, Tor prefers
the address family in each bridge line. Returning to ordinary relay selection
restores the configured relay address preference.

The proxy reserves `127.128.0.0/9` and `fd00:746f:7200::/104` when a Go
method is registered or the state directory contains saved route assignments.
Requests for retired addresses fail. With persistent Tor state, the driver saves
route assignments in `tor-driver-routes-v1` in the state directory. This keeps
Tor's learned bridge identity associated with the same logical address across
restarts and changes in list order. The file stores digests of bridge settings.
Back it up or restore it together with the rest of the Tor state.

For each managed method in the active bridge list, Tor receives a
`ClientTransportPlugin` entry with the child-visible executable path.
The path must fit in one Tor token. Supply
obfs4 options such as `cert` and `iat-mode` in `Bridge.Args`. Argument names
accept ASCII letters, digits, underscores, and hyphens. Managed argument
values accept printable ASCII except spaces, quotes, backslashes, and
number signs. The encoded arguments must fit the 510-byte SOCKS5 limit.

`SetBridges` replaces the bridge list using the startup registrations.
Pass an empty `BridgeConfig` to return to ordinary relay selection.
An unregistered method causes startup or the bridge update to fail.

When updating an obfs4 configuration from v0.2.0, replace `tor.Obfs4` with
`"obfs4"`. Move `Obfs4Certificate` to `Args["cert"]` and set
`Args["iat-mode"]` to the decimal string for the former `IAT` value.
Move runtime transport registrations from `BridgeConfig.Transports` to
`Config.Transports` before calling `Start`.

## Persistent Tor state

Use a stable owner and slot with the persistent root:

```go
cfg.StateDirectory = gobox.Path{
    Root: gobox.Persistent,
    Rel:  "tor-state",
}
```

The backend and host policy control persistence, quotas, ownership, and safe
reuse after cleanup failures.

Other fields configure Tor protocol behavior. They include timeouts, circuit
and connection padding, address-family policy, relay selection, bridge lines,
bandwidth limits, logging, and onion traffic policy. Zero values select the
documented conservative defaults in `api.go`.
