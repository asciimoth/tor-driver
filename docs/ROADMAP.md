# Roadmap

The current code implements the first client/onion-hosting slice. The following
work is ordered so the next changes establish evidence before broadening the API.
The Linux local baseline now passes formatting, module checks, vet, race tests,
lint, a Windows cross-build, and the offline Tor lifecycle test. The remaining
items below are not complete.

## 1. Establish a reproducible build and lifecycle baseline

Implementation status: the pinned Linux and Windows hosted gates, injected
lifecycle/race fixtures, parser fuzzers, Bine conformance corpus, and retained
resource checks are present. The automatic gates must pass in the hosting
service, and the manual public-network and private-bridge jobs must be recorded,
before the acceptance condition is complete.

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

Acceptance: both platforms compile and run their unit suite; actual processes
are reaped, discarded resources close, and a documented version matrix passes
the offline and public-network e2e gates.

## 2. Qualify routing and add OS enforcement

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

Acceptance: packet-level observation or OS denial confirms no external socket
escapes the intended boundary throughout failure and recovery tests. Explicitly
distinguish protocol-level routing from OS containment in supported profiles.

## 3. Complete onion-service and readiness features

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

Acceptance: identities survive intentional restart when configured, deleted
services disappear, publication waits are cancellable, and port/key state
remains consistent through controller failures.

## 4. Broaden the typed client configuration deliberately

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
