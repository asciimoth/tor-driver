# Testing and validation status

## Local validation status

The following checks passed on 2026-09-23 in the Nix development shell:

- Go 1.26.7 on Linux/amd64: formatting, `go mod tidy -diff`, `go vet ./...`,
  `go test -race -timeout 2m ./...`, and `golangci-lint` 2.13.1.
- `typos` and a Windows/amd64 cross-build with CGO disabled.
- The offline lifecycle e2e test with Tor 0.4.9.11. This test started a real Tor
  process, authenticated the controller, managed an ephemeral onion service,
  and shut down the process without public-network access.

Windows runtime, public Tor, obfs4, controlled-network, and packet-level routing
tests have not run. These gaps prevent a production-support claim.

## First verification pass

Enter the Nix development shell and run the complete local gate:

```sh
just check
```

This command formats the source and tidies the module before it runs typo
checks, lint, vet, race tests, the offline Tor test, and a Windows cross-build.

To run the main underlying commands without `just`, install Go 1.25.5 or later,
`golangci-lint`, `typos`, and Tor, then use:

```sh
go mod tidy
typos
golangci-lint fmt ./...
golangci-lint run ./...
golangci-lint run --build-tags=e2e ./...
go vet ./...
go vet -tags=e2e ./...
go test -race -timeout 2m ./...
go test -race -tags=e2e -run '^TestTorOffline' -v -timeout 2m .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

The race command needs a suitable native C compiler. On Windows, run the native
`go test` and `go build` commands as well; cross-compiling is not runtime
validation. Review module and formatting changes before you commit them.

## Included unit tests

| Area | What the tests exercise |
| --- | --- |
| Private controller | SAFECOOKIE proofs and tamper rejection; no response to an unverified server; multiline/data replies and interleaved events; post-send cancellation closes control; injection rejection. |
| Outgoing gate | Nil blocking, error latch and explicit rearm, replacement closing both sides, cancellation of pending dials, rejection/closure of a deliberately late successful result, close notifications. |
| Upstream SOCKS proxy | Real local TCP handshake, username/password authentication, forwarding only through the injected fake backend, removal blocking further requests, no unauthenticated access. |
| Client Networks | On-wire isolation credentials across sessions and fresh-connection mode, hostname forwarding without resolution, loopback traversing SOCKS, unsupported UDP, live socket and handshake closure, concurrent create/close. |
| Configuration | Transport whitelist, ignored bridges without direct fallback, numeric-only bridge endpoints, mandatory proxy/authentication values, malformed supported bridge options and control-character rejection. |

Loopback sockets and net.Pipe in tests are deliberate direct test fixtures. Core
production code does not use native network constructors. Credential tests verify
the inputs to Tor isolation, not actual circuit IDs; a controlled Tor network is
needed for the latter.

## Real Tor, no public network

Install Tor separately. This test launches an actual daemon, authenticates with
its temporary cookie, creates/deletes a v3 service and closes the process. Its
outgoing Network is nil, so public bootstrap is unnecessary:

```sh
TOR_BINARY=/usr/bin/tor go test -tags=e2e -run '^TestTorOffline' -v -timeout 2m .
```

If TOR_BINARY is unset, the fixture searches PATH. A missing executable produces
an explicit test skip. Require a real path in release automation so a skip does
not pass unnoticed.

PowerShell equivalent:

```powershell
$env:TOR_BINARY = 'C:\Tor\tor.exe'
go test -tags=e2e -run '^TestTorOffline' -v -timeout 2m .
```

Run as a normal user. A root Linux test process must set TOR_TEST_UID and
TOR_TEST_GID to a non-root identity. Ensure Tor and any executable parent paths
are accessible to that identity. Tests use private temporary daemon state.

## Public Tor, two daemons

This is explicit opt-in because it connects to the public Tor network. It starts
one HTTP onion service and requests it through the second Driver, checks that
both daemons use their injected outgoing Networks, removes the client's outgoing
Network, verifies a new request fails, installs another Network, and retries the
onion request successfully:

```sh
TOR_BINARY=/usr/bin/tor TOR_DRIVER_LIVE=1 \
  go test -tags=e2e -run '^TestTorOnion' -v -timeout 15m .
```

Public-network tests depend on reachability, local clock, bridge/relay health,
bootstrap and descriptor propagation. A timeout is a test failure requiring
diagnosis, not proof of a library defect or evidence that the test passed. The
`just check` recipe does not run this test. Run `just test-e2e` to opt in.

## Obfs4 routing contract

Supply a real bridge and the exact obfs4 binary intended for deployment:

```sh
export TOR_BINARY=/usr/bin/tor
export TOR_DRIVER_LIVE=1
export TOR_OBFS4_BINARY=/usr/bin/obfs4proxy
export TOR_BRIDGE_ADDRESS='NUMERIC_IP:PORT'
export TOR_BRIDGE_FINGERPRINT='40_HEX_DIGITS'
export TOR_BRIDGE_CERT='BASE64_CERTIFICATE'
go test -tags=e2e -run '^TestTorObfs4' -v -timeout 8m .
```

The test rejects any requested upstream destination other than the supplied
bridge and requires successful Tor bootstrap through the injected proxy. Bridge
values are not bundled or printed. For IPv6 use bracketed IP:port notation.

This test establishes that the configured route was used. Counting connections
inside a proxy cannot prove that no child opened an additional socket outside
it. A release qualification should additionally capture IPv4/IPv6/DNS traffic
or deny child egress at the OS layer, including while the outgoing Network is
removed, the proxy is unreachable, credentials are wrong, and the PT fails.
No such packet-level test has been executed for this starter.

## CI

No hosted CI workflow is present. Run the commands in this document before each
commit. Add Linux and Windows CI before release, and keep public-network and
private-bridge tests as explicit opt-in jobs. Follow ROADMAP.md for the additional
release gates.
