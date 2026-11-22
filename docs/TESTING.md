# Testing

Run the complete local gate in the pinned development environment:

```sh
nix develop
just check
```

The normal suite uses deterministic sandbox test doubles for error injection
and lifecycle checks. Restart tests use the debug sandbox filesystem to check
persistent bridge assignments, failed writes, and damaged state. Run
`just test-offline` for bridge transport tests with the `gobox/debug` backend,
Tor, and lyrebird. The injected network records
connection attempts in memory. The tests cover method selection, managed
obfs4, live bridge replacement, and a return to ordinary relay selection.

The separate public-network test waits for a real Tor circuit:

```sh
go test -tags=e2e -run '^TestTorThroughDebugGoboxBackend$' -v -timeout 5m .
```

Set `TOR_BINARY` or `TOR_OBFS4_BINARY` to select Tor or lyrebird outside
`PATH`. The debug backend inherits host authority and provides no security
boundary.

Sandbox security and platform containment tests belong to the selected
production `gobox` backend. This repository tests only that the driver uses the
capability correctly: typed programs and paths, sandbox filesystem access,
sandbox loopback sockets, command-tree kill, and sandbox close.

The regular suite also covers control parsing, proxy authentication, outbound
replacement, circuit isolation credentials, onion-service lifecycle, bridge
validation, redaction, cancellation, and cleanup failure reporting.
