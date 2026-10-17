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

## Managed transports

Only obfs4 is accepted. Register it with a host-approved program ID:

```go
cfg.Transports = []tor.TransportConfig{{
    Kind:    tor.Obfs4,
    Program: "obfs4",
}}
```

The selected sandbox template must make this program available. Tor receives
the child-visible path from `Sandbox.ProgramPath`. Runtime bridge changes can
use only transport programs approved when `Start` ran.

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
