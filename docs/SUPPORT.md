# Support and release policy

## Release line

The project uses semantic version tags. Before version 1.0, a minor release can
change the public Go API. Patch releases in one minor line contain compatible
fixes. The latest tagged minor line is the supported line. Older minor lines do
not receive routine fixes.

This policy describes maintenance and test scope. It is not a security audit or
a promise that Tor provides anonymity for every application design.

## Supported environments

Linux amd64 and Windows amd64 are the runtime targets. The exact Go, Tor,
obfs4, operating-system, and runner versions are in the reproducible matrix in
[TESTING.md](TESTING.md). Other Go targets can compile, but they are not release
targets until they have a recorded native runtime gate.

Applications must supply a qualified `gobox` backend for each supported
platform. Sandbox protection, host privileges, and operating-system support are
properties of that backend and its host policy. The `gobox/debug` backend is
for tests and examples only and provides no security boundary.

## Release qualification

A version tag must identify one exact commit. Before maintainers create the
tag, all automatic jobs in `.github/workflows/ci.yml` must pass for that commit:

- the pinned Linux `just check-ci` gate;
- the minimum supported Go build and unit suite;
- the tagged real-Tor test through `gobox/debug`; and
- the native Windows unit and build gate.

The manual Linux and Windows public-network jobs must also pass for the same
commit. Their workflow summaries record the revision, runner, Go version, Tor
version, and test scope. Public-network results are not inferred from an older
revision. Release notes must link these run records and state any
environment-dependent test that was not run. A release is not qualified when a
required test is skipped.

The repository is a Go library and does not publish Tor or transport binaries.
Applications must pin and qualify those trusted executables separately.

## Compatibility and reports

Supported releases require Go 1.25.5 or later and Tor 0.4.8 or later. A later
Tor release can change defaults, so the generated typed settings and offline
gate remain part of each release qualification.

Use the repository issue tracker for reproducible defects and compatibility
reports. Do not include bridge credentials, onion private keys, private state
paths, or unredacted Tor logs. There is no guaranteed response time.
