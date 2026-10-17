# tor-driver

`tor-driver` owns a Tor client daemon, exposes closable `gonnect.Network`
instances, hosts v3 onion services, and sends Tor relay connections through an
explicitly supplied `gonnect.Network`.

> [!WARNING]
> This library is experimental and has not been audited. Do not use it for
> security-critical applications.

## Sandbox integration

The library launches Tor only through
[`github.com/asciimoth/gobox`](https://github.com/asciimoth/gobox). The
embedding application owns the sandbox service, owner identity, executable
mapping, and protection policy. It gives `tor-driver` a
`gobox.OwnerSandboxes` capability. The driver cannot select a native executable,
change the child identity, or fall back to ordinary host execution.

The default logical IDs are slot `tor`, template `tor`, and program `tor`.
Override them with `Config.SandboxSlot`, `Config.SandboxTemplate`, and
`Config.TorProgram`. A managed transport uses `TransportConfig.Program`.
Use a different slot for each concurrently active `Driver` under one owner.

The Tor program accepts two typed path inputs named `defaults-torrc` and
`torrc`. Host policy converts them to these arguments:

```text
--defaults-torrc <defaults-torrc path> -f <torrc path>
```

Working files, persistent state, process cleanup, and loopback sockets use the
acquired sandbox. Select persistent state with a sandbox path:

```go
cfg.StateDirectory = gobox.Path{Root: gobox.Persistent, Rel: "state"}
```

Closing a `Driver` closes its sandbox instance. It does not close the supplied
owner capability, outbound network, logger, clock, random source, or key store.

Package `gobox/debug` is suitable for tests and local examples only. It starts
ordinary host processes and provides no security boundary. See
[`examples/internal/debugtor`](examples/internal/debugtor/debugtor.go) for a
complete debug configuration.

## Features

- Foreground Tor lifecycle with SAFECOOKIE authentication and owned shutdown.
- A fixed authenticated SOCKS5 proxy whose external dial path is the injected
  outbound network.
- Runtime outbound replacement and optional failure latching.
- Per-session or per-connection Tor circuit isolation.
- Tor DNS resolution without a local DNS fallback.
- Runtime v3 onion services, publication events, key persistence, client
  authorization, mutable virtual ports, and draining.
- Typed configuration for padding, address families, relay selection, bridges,
  and obfs4.
- Typed startup, bootstrap, transport, terminal, and shutdown events.

## Basic use

```go
deps := tor.Dependencies{
    Sandboxes: ownerSandboxes,
    Clock:     clock,
    Random:    rand.Reader,
    Logger:    logger,
    Outbound:  outgoing,
}

driver, err := tor.Start(ctx, tor.Config{}, deps)
if err != nil {
    return err
}
defer driver.Close()
```

Call `WaitReady` before application traffic. `SetOutbound(nil)` closes active
proxy sessions and blocks new relay connections without stopping Tor.

## Development

```sh
nix develop
just check
```

The `e2e` test tag runs a real Tor daemon through `gobox/debug`. Set
`TOR_BINARY` when Tor is not in `PATH`.

## Documentation

- [Operational examples](examples/README.md)
- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Testing](docs/TESTING.md)
- [Support policy](docs/SUPPORT.md)
