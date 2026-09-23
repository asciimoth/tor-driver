# Testing and validation status

## Reproducible version matrix

The automatic workflow in `.github/workflows/ci.yml` uses these targets. Update
the workflow, this table, and the Nix lock in one change when a version changes.

| Gate | OS | Go | Tor | obfs4 implementation | Run policy |
| --- | --- | --- | --- | --- | --- |
| Pinned Linux baseline | Ubuntu 24.04 amd64 host; packages from `flake.lock` | 1.26.7 | 0.4.9.11 | lyrebird 0.8.1 | Each push and pull request |
| Minimum Go compatibility | Ubuntu 24.04 amd64 | 1.25.5 | Not used | Not used | Each push and pull request |
| Windows runtime baseline | Windows Server 2022 amd64 | 1.25.5 | 0.4.9.12 from Tor Expert Bundle 15.0.23 | lyrebird 0.8.1 in the bundle; not used by the offline gate | Each push and pull request |
| Private Docker network and Linux containment | Debian 13 amd64 container on Ubuntu 24.04 | 1.25.5 | 0.4.9.12 from Tor Expert Bundle 15.0.23 | lyrebird 0.8.1, executable SHA-256 `ee13ec155cf9b131a3e1b87bd6d697a10c42d04f2eaaeab6b1590c9971d41421` | Each push and pull request |
| Public two-daemon gate | The pinned Linux and Windows targets above | As above | As above | Not used | Manual workflow input |

The Windows archive is pinned by SHA-256 in the workflow. The Linux package
closure is pinned by `flake.lock`. The hosted runner image can receive kernel
and platform updates; the workflow prints all user-space versions in its log.
Linux amd64 and Windows amd64 are the step 1 runtime targets. Other systems can
compile, but they are not in this support matrix.

Linux developers can also run the native Windows baseline in a disposable
Windows Server 2022 QEMU/KVM guest. This local gate tests the current working
tree, including eligible modified and untracked files. It is separate from
`just check` and does not replace the hosted Windows gate. See
[`dev/winvm/README.md`](../dev/winvm/README.md) for licensed-media setup,
locked inputs, daily use, artifacts, and failure recovery.

## Local validation status

The following checks passed on 2026-09-23 in the Nix development shell:

- Go 1.26.7 on Linux/amd64: formatting, `go mod tidy -diff`, `go vet ./...`,
  `go test -race -timeout 2m ./...`, and `golangci-lint` 2.13.1.
- `typos` and a Windows/amd64 cross-build with CGO disabled.
- The offline lifecycle e2e test with Tor 0.4.9.11. This test started a real Tor
  process, authenticated the controller, changed a service port mapping, and
  recreated one stored onion identity after an intentional process restart. It
  then shut down without public-network access. The e2e fixture also checks
  process reaping and release, local socket closure, temporary-directory removal,
  and driver goroutine settlement.
- The Linux public-network test with Tor 0.4.9.11. Two daemons bootstrapped, an
  HTTP request reached the ephemeral onion service, outbound access was removed,
  and a replacement outgoing Network restored access.
- The Linux amd64 Docker e2e test with Tor 0.4.9.12 and lyrebird 0.8.1. A local
  Chutney network bootstrapped with Docker external networking disabled. Direct
  and obfs4 clients reached a loopback HTTP server through the private exit.
  A protected service received a confirmed descriptor-upload event, and Tor
  accepted the typed client-authorization add and remove commands. Tests also
  checked circuit IDs, distinct isolation groups, repeated direct-network
  replacement, obfs4 removal/replacement, proxy failure recovery, wrong proxy
  credentials, missing proxy support, and PT crash.
- Controlled PT processes attempted direct IPv4, IPv6, and DNS traffic. The
  network-disabled profile denied each attempt. A second privileged-container
  profile ran `ContainedSystem` with a normal parent network; its per-cgroup
  nftables counters recorded the IPv4, IPv6, and DNS denials.
- Injected lifecycle tests cover startup failures, malformed and partial port
  and cookie files, missing SAFECOOKIE, control loss, child failure, shutdown
  timeout, and cleanup errors. The race suite covers simultaneous replacement,
  close, dial, service creation, subscription callbacks, and unsubscription.
- Five-second fuzz gates cover control replies, the SOCKS greeting,
  authentication and CONNECT parser, and typed bridge validation. A fixed
  control-reply corpus is also compared with Bine 0.2.0.

On 2026-09-24, `nix flake check` also passed with a fixed-output Go module
proxy. The check runs the Go pre-commit gates without network access and runs
the Windows VM host-script tests without starting Windows.

The hosted workflow and Windows runtime gate were added on 2026-09-23. A hosted
result is authoritative only for the revision in its GitHub Actions run. The
Windows runtime job and both manual public-network jobs write their revision,
runner, Go version, Tor version, and successful test scope to the workflow
summary. The Windows runtime and public-network results are not part of this
Linux qualification. The Docker gate qualifies the deployable Linux
`ContainedSystem`; Windows does not yet have an equivalent contained adapter.

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
just fuzz
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

The race command needs a suitable native C compiler. On Windows, run the native
`go test` and `go build` commands as well; cross-compiling is not runtime
validation. Review module and formatting changes before you commit them.

Run the controlled network when Docker is available. Its second profile needs
privileged-container support for a private network namespace, cgroup v2, and
nftables:

```sh
just test-e2e-docker
```

## Private Docker network

`e2e/run.sh` builds a pinned Linux amd64 image and starts a local Chutney
network. The infrastructure has four directory authorities, one bridge
authority, one exit, and one obfs4 bridge. Chutney generates all keys and the
bridge certificate for the current run.

The first container runs with Docker network mode `none`. Only its loopback
interface is available during network bootstrap and Go tests. The direct client
must use the injected outgoing Network for its relay connections. The obfs4 client
rejects every requested outgoing destination except the generated bridge. Both
clients make an HTTP request through the private exit to a loopback server.

The failure matrix confirms that Tor supplies authenticated `TOR_PT_PROXY`, that
wrong credentials never reach the outbound backend, and that missing proxy
support and PT crashes cannot bootstrap. It also removes and replaces the obfs4
outgoing Network and recovers from an initial backend failure. A test-only PT
attempts native IPv4, IPv6, and DNS connections. These attempts fail at the
whole-container network boundary.

The same private network creates a protected onion service and waits for Tor's
descriptor-upload event. It also sends typed client-authorization add and remove
commands to the real controller. This check does not claim that the small test
network provides stable end-to-end onion routing for restricted discovery.

The second container has a normal Docker bridge but starts Tor and the test PT
in a cgroup through `ContainedSystem`. It configures a controlled IPv6 route and
requires nftables denial counters for IPv4, IPv6, and DNS attempts. The parent
test process remains outside the filtered cgroup. This distinguishes
per-process OS containment from protocol-level proxy routing.

The generated authority lines enter the driver through an `e2e`-only
filesystem wrapper. They are not part of `Config`, and the production API does
not expose raw torrc text.

## Included unit tests

| Area | What the tests exercise |
| --- | --- |
| Private controller | SAFECOOKIE proofs and tamper rejection; no response to an unverified server; multiline/data replies and interleaved events; post-send cancellation closes control; injection rejection. |
| Outgoing gate | Nil blocking, error latch and explicit rearm, replacement closing both sides, cancellation of pending dials, rejection/closure of a deliberately late successful result, close notifications. |
| Upstream SOCKS proxy | Real local TCP handshake, username/password authentication, forwarding only through the injected fake backend, removal blocking further requests, no unauthenticated access. |
| Client Networks | On-wire isolation credentials across sessions, destinations, ports, and fresh-connection mode; hostname forwarding without resolution; loopback traversing SOCKS; unsupported UDP; live socket and handshake closure; concurrent create/close. |
| Configuration | Typed padding, IP, onion, resource, relay-port, and exit-exclusion mappings; transport whitelist; ignored bridges without direct fallback; numeric bridge endpoints; mandatory proxy/authentication values; malformed option and control-character rejection. |
| Runtime bridges | Ordered network disable, all-or-nothing typed replacement, rollback after enable failure, and proof that rejected bridge mode does not re-enable direct guards. The private-network gate changes a live direct client to obfs4. |
| Onion services | Expanded-key conversion and text formats, injected persistence and storage failure cleanup, typed host/client authorization, descriptor waits/events, port removal/reopen and rollback, stream-limit policy, drain, and close subscriptions. |
| Linux direct adapters | `openat2` symlink rejection, fd-relative removal, private modes, pidfd/process cleanup, and generated cgroup/nftables rules for both IP families. |

Loopback sockets and net.Pipe in tests are deliberate direct test fixtures. Core
production code does not use native network constructors. Unit tests verify the
SOCKS isolation credentials. The Chutney test reads test-build-only circuit
status and confirms that different credentials never share a circuit ID.

## Real Tor, no public network

Install Tor separately. These tests launch actual daemons, authenticate with
their temporary cookies, change a live v3 service port map, recreate a stored
identity across an intentional process restart, delete the services, and close
the processes. Their outgoing Network is nil, so public bootstrap is
unnecessary:

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

## External obfs4 routing contract

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
inside a proxy cannot prove that no child opened another socket. The private
Docker gate supplies the stronger evidence: a network-disabled profile covers
the full PT failure/recovery matrix, and a separate `ContainedSystem` profile
records per-cgroup IPv4, IPv6, and DNS denials while its parent retains network
access.

## Hosted CI

The `CI` workflow runs the complete pinned Linux gate, the private Docker and
Linux containment profiles, a Windows unit/build gate, and the real-Tor offline
lifecycle test on Windows. A skipped offline test
cannot pass because the workflow always supplies an absolute `TOR_BINARY` from
the checksum-verified Tor Expert Bundle.

Start the workflow manually with `run_public_network` to run the two-daemon HTTP
test on both supported operating systems. Public-network failures need
diagnosis and do not block ordinary pull requests automatically. The private
Docker network needs no repository secrets and runs on each push and pull
request. Each successful Windows runtime or manual public-network job records
a qualification table in the GitHub Actions workflow summary.
