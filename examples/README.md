# Operational examples

The examples use the `gobox/debug` backend so that they are easy to run. This
backend provides no security boundary. A production application must replace
it with a protected `gobox` backend and host-owned policy.

The `-tor` option selects the Tor executable. An empty value searches `PATH`.
The commands use the public Tor network unless their outbound `gonnect.Network`
uses another route.

- `custom-outbound` counts relay connections.
- `long-lived-state` selects the sandbox persistent root for guard state.
- `http-pooling` compares Tor isolation with HTTP connection pooling.
- `service-only` hosts an onion service without creating a client network.
- `onion-http` starts a server and client daemon.

For example:

```sh
go run ./examples/long-lived-state -state "$PWD/private-tor-state"
```
