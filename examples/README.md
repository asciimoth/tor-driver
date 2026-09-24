# Operational examples

Each command searches the current process `PATH` for Tor. The `-tor` option can
supply an explicit absolute path instead. The commands use the public Tor
network unless their injected outgoing Network provides another route.

- `custom-outbound` wraps a `gonnect.Network` and counts the relay connections
  that Tor requests. Replace the wrapper's backend with a VPN, tunnel, or other
  application-owned gonnect implementation.
- `contained-process` shows custom process containment through the injected
  `Processes` dependency. It selects the fail-closed native adapter. Linux
  needs delegated cgroup v2 and nftables access. Windows needs elevation and
  installs temporary executable-scoped firewall rules. An application-specific
  adapter can set `Dependencies.Processes` in the same way.
- `long-lived-state` keeps guard and consensus state across restarts. Give each
  Driver a separate private state directory.
- `http-pooling` shows the difference between Tor circuit isolation and HTTP
  connection pooling. A pooled HTTP connection stays on its existing Tor
  stream, even with per-connection circuit isolation.
- `service-only` hosts an onion HTTP service without creating a client Network.
  The Tor process still needs an outgoing Network to reach the Tor network.

For example:

```sh
go run ./examples/long-lived-state -state "$PWD/private-tor-state"
```
