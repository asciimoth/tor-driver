# Testing

Run the complete local gate in the pinned development environment:

```sh
nix develop
just check
```

The normal suite uses deterministic sandbox test doubles for error injection
and lifecycle checks. The tagged end-to-end test uses the official
`gobox/debug` backend and a real Tor executable:

```sh
go test -tags=e2e -run '^TestTorThroughDebugGoboxBackend$' -v -timeout 5m .
```

Set `TOR_BINARY` when Tor is not in `PATH`. The debug backend is intentionally
unsafe: it inherits host authority and provides no security boundary.

Sandbox security and platform containment tests belong to the selected
production `gobox` backend. This repository tests only that the driver uses the
capability correctly: typed programs and paths, sandbox filesystem access,
sandbox loopback sockets, command-tree kill, and sandbox close.

The regular suite also covers control parsing, proxy authentication, outbound
replacement, circuit isolation credentials, onion-service lifecycle, bridge
validation, redaction, cancellation, and cleanup failure reporting.
