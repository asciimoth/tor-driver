# Roadmap

The current code implements the first client/onion-hosting slice. The following
work is ordered so the next changes establish evidence before broadening the API.
The local Linux baseline passes formatting, module checks, vet, race tests,
lint, a Windows cross-build, and the offline Tor lifecycle test. Step 1 is
implementation-complete for Linux and Windows. Step 2 is implementation-complete
for Linux and Windows. Step 3 is implementation-complete.

## 1. Establish a reproducible build and lifecycle baseline

Implementation status: complete. The pinned hosted gates, injected
lifecycle/race fixtures, parser fuzzers, Bine conformance corpus, and
retained-resource checks are present. The Linux offline, private-network, and
public two-daemon gates passed on 2026-09-23. Native Windows tests cover Job
Object descendant cleanup and private directory ACLs. The shared Windows gate
runs in hosted CI and in a disposable local Windows Server 2022 VM. The hosted
Windows runtime gate and both hosted public-network gates write
revision-specific qualification records to the workflow summary. The
public-network gates remain explicit manual runs.

- Reproduce the current formatting, module, vet, unit, race, lint, cross-build,
  and offline Tor results in hosted CI. Record a supported Go, Tor, obfs4, and OS
  version matrix instead of relying on one local environment.
- Run offline lifecycle e2e on Linux and Windows, followed by the two-daemon HTTP
  example/e2e. Inspect for retained child processes, goroutines, sockets and
  temporary files after successful startup and every startup failure stage.
- Add injected-process/filesystem integration fixtures for malformed/partial
  cookie and port files, spawn failure, missing SAFECOOKIE, lost control, failed
  listener, child crash, shutdown timeout and cleanup failure. Verify rollback
  and error reporting without requiring Tor in these tests.
- Extend race tests to simultaneous SetOutbound/Close/Dial and Service
  New/Listen/Close, synchronous subscriptions and unsubscribe races. Include
  blocked, canceled and late-returning network adapters.
- Fuzz the private control parser, proxy greeting/auth/CONNECT parser, and typed
  bridge validation. Cross-check controller behavior with established clients.

Acceptance: supported revisions compile and run their unit suites; actual
processes are reaped, discarded resources close, and the documented version
matrix supplies offline and public-network results on Linux and Windows. The
Linux-only private-network gate supplies deterministic routing evidence. A
revision is qualified only when its required hosted jobs and the applicable
manual public-network jobs pass; the workflow summary records that evidence.

## 2. Qualify routing and add OS enforcement

Implementation status: complete. The approved Docker
lyrebird binary has an individual SHA-256 pin. The Chutney gate covers direct
and obfs4 bootstrap, authenticated PT proxy use, PT and proxy failures, wrong
credentials, removal, repeated replacement, and circuit-ID isolation evidence.
A controlled PT verifies IPv4, IPv6, and DNS denial in both the network-disabled
fixture and the deployable cgroup/nftables profile. The native Linux adapter uses
pidfds and a cgroup when available, and its filesystem operations use fd-relative
Linux APIs that reject symlink replacement. Windows uses a restricted token and
executable-scoped firewall rules, qualifies nested Jobs, uses documented thread
resume APIs, and applies private directory descriptors during creation.

- Pin approved obfs4 builds and test authenticated TOR_PT_PROXY support, proxy
  failure, missing proxy support, PT crash, wrong credentials, removal and
  replacement. Verify every transport-created IPv4/IPv6/DNS connection.
- Use Chutney or another controlled Tor network for deterministic bootstrap,
  stream/circuit ID checks, distinct Network isolation and repeated replacement.
  Keep testing-network Tor options behind a test-only internal fixture, never a
  public raw-torrc option.
- Implement an optional contained Process adapter. On Linux, use a network
  namespace/firewall and reliable process supervision; on Windows, use a
  restricted token/AppContainer and suitable network controls. Account explicitly
  for runtime onion backing ports and PT local endpoints.
- Replace Linux process-group-only cleanup with cgroup/pidfd-assisted supervision
  where available. Validate Windows suspended launch and Job behavior on hosts
  already running inside a Job. Use documented resume mechanisms where practical.
- Strengthen filesystem operations against path-replacement races with appropriate
  OS APIs, and create Windows private directories with a private security
  descriptor atomically rather than tightening ACLs after creation.

Acceptance: Linux OS denial counters confirm that controlled external IPv4,
IPv6, and DNS attempts cannot leave the contained Tor/PT cgroup. The isolated
Docker profile supplies a second whole-container denial boundary during the PT
failure and recovery matrix. Documentation distinguishes protocol routing from
the optional OS containment profile. Windows installs fail-closed rules for each
approved Tor/PT executable, keeps required loopback endpoints available, and
disables unnecessary token privileges.

## 3. Complete onion-service and readiness features

Implementation status: complete. Driver and Service publish bounded typed
events, stored service identities use injected storage, v3 restricted discovery
is typed in both directions, and acknowledged mapping replacement supports
independent port removal and reopen. Services also support close subscriptions,
immediate Close, explicit Drain, and both MaxStreams policies. Tor does not
expose the authorized client identity for an accepted stream, so the API does
not claim that metadata. The platform-independent tests and the real-Tor
offline gate run on Linux and Windows. The controlled private-network gate
remains Linux-only.

- Add typed descriptor-publication/readiness events so callers can wait for
  publication rather than probe. Report bootstrap progress, PT errors and
  terminal process causes without exposing raw sensitive controller events.
- Add persistent v3 identities with a typed key representation and injected key
  storage. Tor's expanded ED25519 private-key format is not interchangeable with
  a generic Go Ed25519 seed; specify and test conversions before exposing them.
- Add typed client authorization for hosting and accessing protected services.
- Support independently removable/reopenable virtual ports using acknowledged
  mapping updates while preserving the rule against mapping to recycled ports.
- Consider Service close subscriptions, explicit drain behavior, MaxStreams
  policies and authenticated metadata for accepted connections.

Acceptance: the real-Tor offline gate recreates one stored identity across an
intentional process restart and exercises port removal/reopen. Injected tests
cover deleted services, cancellable publication waits, key-store failures, and
mapping rollback after controller rejection. The private-network gate waits for
publication of a protected-service descriptor and validates both typed client
authorization commands against Tor.

## 4. Broaden the typed client configuration deliberately

Implementation status: the non-Windows scope is complete. The public inventory
includes typed padding, reachable relay ports, exit exclusions, pending-circuit
and CPU limits, IPv4/IPv6 preferences, onion target policy, and destination
isolation. Runtime bridge replacement uses only startup-approved executables,
disables networking before an all-or-nothing update, and remains disabled after
each failure. The
private-network gate changes a live direct client to obfs4. Per-Network reuse
ages, literal circuit pinning, additional transports, and a production Bine
adapter were evaluated and deliberately not exposed. `CONFIGURATION.md` records
the reasons and the future qualification requirements.

- Inventory common client options with compatibility/minimum-version metadata:
  padding controls, constrained upstream ports, additional relay-selection
  types, bootstrap/resource limits, IPv6 preferences and onion client settings.
- Add typed runtime bridge changes only with a transactional rollback strategy
  and tests that bridge-mode failure cannot enable direct guards.
- Evaluate per-Network SOCKS listener policies for differing reuse ages and other
  supported isolation flags. Keep literal circuit pinning a separate advanced
  API with stream-event handling, explicit circuit lifetime and tested failures.
- Add other transports one at a time only after implementation-specific proxy
  qualification. Supporting a protocol name does not automatically authorize
  arbitrary binaries, arguments or network behavior.
- Evaluate an internal Bine controller adapter against the private parser on
  coverage, cancellation, effects injection and maintenance cost.

Acceptance: every public option has a fixed Go type, validation, a documented
Tor mapping, compatibility behavior and appropriate integration coverage.

## 5. Packaging and operational polish

- Expose bounded typed diagnostics for outgoing attachment failures and graceful
  shutdown errors. Improve startup diagnostics without logging credentials,
  full bridges or onion private material.
- Add examples for custom outgoing gonnect backends, custom process containment,
  long-lived guard state, HTTP pooling choices and service-only applications.

Acceptance: documented support policy and automated gates justify a versioned
release, and the README validation notice reflects recorded successful results.
