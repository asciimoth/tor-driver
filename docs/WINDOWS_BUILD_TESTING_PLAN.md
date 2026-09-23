# Windows build and test plan

## 1. Goal

Add an explicit local command that lets a Linux developer build and test this
repository in a Windows virtual machine. The first target is Windows Server
2022 on amd64, which matches the existing GitHub Actions OS family. The local
ISO will not have the exact patch level or image customizations of the hosted
`windows-2022` runner, so keep hosted CI as a separate required gate.

The VM gate must test the current working tree, including modified and
untracked source files. It must run the Go toolchain and tests in Windows. The
existing Linux-to-Windows cross-build remains a fast compile check, but it is
not the native Windows gate.

The normal Linux gate must not require a Windows license, a Windows image, or
KVM. Keep `just check` usable in the current Nix development shell. Run the VM
gate with a separate, explicit command.

## 2. Repository findings

- The module requires Go 1.25.5 or later.
- The supported Windows target is `windows/amd64`.
- The repository has no cgo code. The current cross-build correctly uses
  `CGO_ENABLED=0`.
- `direct/process_windows.go` contains native Windows behavior. It creates a
  Job Object, starts Tor in a suspended state, assigns it to the job, and then
  resumes it. It also sets private Windows ACLs.
- `just build-windows` checks that all packages compile for Windows, but it
  cannot validate Job Objects, ACLs, process cleanup, or runtime behavior.
- The `windows-baseline` CI job already performs a native Windows build, unit
  tests, vet, and one offline Tor lifecycle test on Windows Server 2022.
- The Windows CI job uses Go 1.25.5 and Tor Expert Bundle 15.0.23. The Tor
  archive SHA-256 is already pinned in `.github/workflows/ci.yml`.
- The offline Tor tests do not use the public Tor network. They are suitable
  for the default VM gate.
- The public onion test is an explicit opt-in. Keep the same rule for the VM.
- The private Docker fixture and the contained-process tests are Linux-only.
  They do not belong in the Windows VM.

The main test gap is local native execution. There are also no focused Windows
unit tests for the process adapter and its ACL behavior.

## 3. Scope decisions

Use direct QEMU/KVM on Linux. Do not put QEMU in a container. The first version
does not need Docker, Podman, libvirt, a host bridge, a TAP device, network
namespaces, nftables, Wintun, a kernel driver, Packer, a Windows C compiler, or
Windows test-signing mode.

Use QEMU user-mode networking. Forward one loopback-only host port to the
guest's SSH service. The repository tests do not change Windows routes, DNS, or
firewall policy, so SSH is sufficient for source transfer and test execution.
Use QEMU Guest Agent for readiness checks, clean shutdown, and recovery when
SSH is unavailable.

Run tests as a dedicated standard Windows user, not as `SYSTEM` and not as an
administrator. This is important for the Windows ACL and child-process paths.
Image provisioning can use administrator rights.

Use an immutable base qcow2 image and a new overlay for each run. Do not keep a
manually changed long-lived test VM.

Do not add Windows race testing in the first version. The Windows race detector
would add a C compiler and cgo toolchain only for that gate. Consider it later
as an optional release check if native Windows race coverage is worth the added
image size and maintenance.

## 4. Proposed layout

Add the following tracked files:

```text
dev/winvm/
  README.md
  config.json
  image-lock.json
  env.example
  Autounattend.xml
  provision.ps1
  test.ps1
  doctor.sh
  build-image.sh
  run.sh
  package-worktree.sh
  tools/qga.py
  tests/host-scripts.sh
```

Use these untracked locations:

```text
${XDG_CACHE_HOME:-$HOME/.cache}/tor-driver/winvm/  # base image and input cache
.artifacts/winvm/<run-id>/                         # logs and test results
```

Add narrow `.gitignore` entries for repository-local VM artifacts, overlays,
sockets, payload archives, generated answer media, and local environment
files. Do not use a broad rule that can hide source fixtures.

## 5. Stable commands

Add these recipes to `justfile`:

| Command | Purpose |
| --- | --- |
| `just build-windows` | Keep the current fast `windows/amd64` cross-build. |
| `just winvm-doctor` | Check KVM, QEMU tools, local inputs, hashes, ports, memory, and free disk space. Do not start a VM. |
| `just winvm-image` | Build or reuse the content-addressed Windows Server 2022 base image. |
| `just test-windows-vm` | Test the current working tree in a fresh VM overlay. |
| `just test-windows-vm-public` | Run the opt-in public onion test in a fresh VM overlay. |
| `just winvm-clean` | Remove validated run artifacts and overlays. Do not remove the base image. |
| `just winvm-shell` | Start a retained failed overlay for diagnosis. |

Do not add the VM gate to `just check`. The hosted Windows job stays required
for pushes and pull requests. The local VM command gives developers and agents
native Windows feedback before they push.

## 6. Inputs and version locking

`dev/winvm/config.json` must contain behavior only. It must define the guest
architecture, Windows image name or index, CPU count, memory, disk size, boot
and test timeouts, SSH user, artifact policy, and Windows test commands.

`dev/winvm/image-lock.json` must identify these inputs by version and SHA-256:

- a Windows Server 2022 amd64 installation ISO supplied by the developer;
- a VirtIO Windows driver ISO;
- the Go 1.25.5 Windows amd64 archive;
- Tor Expert Bundle 15.0.23 for Windows amd64;
- a portable OpenSSH package, if the Windows media cannot install a fixed
  OpenSSH version without a network download.

Reuse the Tor version, URL, and SHA-256 from the existing CI configuration.
Do not invent hashes for the Windows or VirtIO ISO. Add a command that prints
their hashes for review, then require the reviewed values in the lock file.

Document machine-local paths in `dev/winvm/env.example`, for example:

```dotenv
WINVM_WINDOWS_ISO=/absolute/path/to/windows-server-2022.iso
WINVM_VIRTIO_ISO=/absolute/path/to/virtio-win.iso
WINVM_CACHE_DIR=/optional/private/cache
```

Do not require a product key in the repository. The developer is responsible
for the Windows license. Do not commit or publish the ISO, base image, overlay,
local SSH key, or generated answer media.

Compute the base-image key from all locked inputs, unattended-install files,
provisioning scripts, and the QEMU machine definition. Record the installed
Windows build, Go version, Tor version, and QEMU Guest Agent version beside the
base image.

## 7. Nix host environment

Extend the existing flake instead of replacing it. Add only host tools needed
by the VM harness:

- QEMU and `qemu-img`;
- OVMF firmware;
- a tool to create the small unattended-install and source media;
- OpenSSH client tools;
- `jq` and Python for the host scripts and QEMU Guest Agent client.

The Nix lock pins these host tools. Do not add an OCI engine, libvirt, Packer,
SWTpm, or MinGW to the first version. Windows Server 2022 does not require a
TPM for this test target.

`nix flake check` must not start Windows. It can run shell checks, configuration
validation, and fake QGA protocol tests.

## 8. Base image build

`just winvm-image` performs these steps:

1. Run `winvm-doctor` and verify every input hash.
2. Create unattended answer media from `Autounattend.xml` and the pinned local
   packages.
3. Install Windows Server 2022 in QEMU with KVM and OVMF.
4. Install the VirtIO storage and network drivers and QEMU Guest Agent.
5. Install the pinned Go and Tor archives without using mutable download URLs
   in the guest.
6. Install and configure OpenSSH for key-only authentication.
7. Create a dedicated, non-administrator `winvm` test account.
8. Install a harness-generated SSH public key for that account. Keep the
   private key only in the private host cache.
9. Disable sleep and interactive first-run prompts. Do not disable Windows
   security controls.
10. Prevent automatic updates during a test run. Update the base image through
    an explicit, reviewed image-lock change instead.
11. Run a guest self-check, remove transient provisioning data, and shut down
    cleanly.
12. Mark the resulting qcow2 base read-only and write its manifest.

Bind the forwarded SSH port to `127.0.0.1` only. Store and verify the guest SSH
host-key fingerprint instead of disabling host-key checks.

The image build must be unattended after the developer supplies the two ISOs.
If unattended installation cannot be made reliable for the selected ISO, a
documented one-time manual installation can be a temporary milestone, but it
is not the final design.

## 9. Per-run flow

`just test-windows-vm` performs these steps:

1. Check the base-image key and acquire an image lock.
2. Create a unique run directory and a qcow2 overlay.
3. Package tracked, modified, and eligible untracked files from the current
   working tree. Exclude `.git`, ignored files, VM data, artifacts, sockets,
   and local secrets. Do not use `git archive HEAD`.
4. Start QEMU headless with KVM, user-mode networking, a unique SSH host port,
   a QMP socket, a QEMU Guest Agent socket, and bounded boot time.
5. Require both a Guest Agent self-check and successful SSH authentication as
   the readiness gate.
6. Copy the source archive into a new guest directory and extract it there.
7. Run `dev/winvm/test.ps1` as the `winvm` account.
8. Copy structured test output, console logs, and guest metadata to the run
   artifact directory.
9. Request a clean shutdown. Use Guest Agent and then a bounded QEMU process
   stop if normal shutdown fails.
10. Delete the overlay after success. Keep it after failure only when the
    configured retention policy requests it, and print the exact
    `just winvm-shell` command.

Use traps for error, timeout, and signal cleanup. Validate every cleanup target
before deletion. Never form a delete target from an empty variable or a broad
glob.

## 10. Native Windows test set

The first version of `test.ps1` must match and then strengthen the current
Windows CI baseline. It must set `CGO_ENABLED=0`, set `TOR_BINARY` to the pinned
absolute guest path, and run:

```powershell
go version
go env
go mod verify
go mod tidy -diff
go vet ./...
go vet -tags=e2e ./...
go test -count=1 -timeout 2m ./...
go test -count=1 -tags=e2e -run '^TestTorOffline' -v -timeout 3m .
go build ./...
```

The script must fail if Tor is absent or its version does not match the image
manifest. Use `go test -list` and `go test -json` to require a pass event, and
no skip event, for every test named `TestTorOffline*`. Save the structured test
events and readable console output.

Move the command list into one PowerShell script that can also be called by the
GitHub Actions Windows job. This prevents the hosted and local Windows gates
from drifting. Keep download and runner setup in the workflow; share only the
repository test logic.

The public command runs only this additional test:

```powershell
$env:TOR_DRIVER_LIVE = '1'
go test -count=1 -tags=e2e `
  -run '^TestTorOnionHTTPAndOutboundReplacement$' `
  -v -timeout 15m .
```

Do not add the external obfs4 test to the default or public VM command. It
requires separate bridge credentials and remains an explicit deployment test.

## 11. Windows-specific tests to add

Add focused tests before the VM gate is considered complete:

1. Add `direct/process_windows_test.go` to start a helper child process through
   `System.Start`, kill it, wait for it, and call `Release` twice. Verify that
   the Job Object also terminates a descendant process.
2. Verify that a non-nil Linux `Identity` is rejected on Windows before a child
   starts.
3. Add `direct/fs_windows_test.go` for private-directory creation, exclusive
   file creation, read limits, cleanup, and relevant Windows path behavior.
4. Inspect the created directory DACL and verify that access is limited to the
   current account and `SYSTEM`, with inherited ACEs disabled.
5. Keep the tests independent of PowerShell command names and local language.
   Use the test executable as the helper child where possible.

Do not require Windows Developer Mode or symlink privileges in the normal
tests. Put any symlink-specific check behind a capability test.

## 12. Diagnostics and artifacts

Every run must record:

- Git revision and dirty status, without source contents;
- base-image content key;
- Windows build and architecture;
- Go and Tor versions;
- QEMU command metadata with secrets removed;
- Guest Agent, QEMU serial, PowerShell, build, vet, and test logs;
- structured Go test events;
- the final exit status and timeout stage.

On failure, also collect current processes, Tor process state, free disk space,
and recent Application and System event-log entries relevant to the test. This
repository does not need packet captures, route dumps, driver state, or virtual
network topology artifacts.

## 13. Harness tests on Linux

Test host behavior without Windows where possible:

- validate `config.json` and `image-lock.json`;
- reject missing inputs and SHA-256 mismatches;
- verify that the base key changes after a relevant input or script changes;
- package a dirty working tree and omit ignored files and local secrets;
- test QGA and QMP parsing with fake Unix sockets;
- propagate guest exit codes and timeouts;
- validate overlay backing files and cleanup targets;
- handle signals without leaving QEMU processes or sockets;
- serialize base-image creation;
- allocate unique run directories and SSH ports.

## 14. Implementation order

1. Add the shared Windows `test.ps1` and use it in the existing hosted Windows
   CI job. Add the focused Windows adapter tests.
2. Add configuration, input locks, `winvm-doctor`, and host-only harness tests.
3. Add the unattended base-image builder and guest self-check.
4. Add disposable overlay execution, working-tree packaging, SSH transfer,
   Guest Agent lifecycle control, and artifact collection.
5. Run the full native baseline twice. Confirm that the second run reuses the
   base but creates a new overlay.
6. Exercise failure cases: bad input hash, boot timeout, failed Go test, lost
   SSH, forced guest shutdown, interrupted host process, and retained overlay.
7. Add the optional public-network command after the offline gate is stable.

## 15. Definition of done

The work is complete when all these statements are true:

- `just winvm-doctor` gives a clear remedy for each missing prerequisite.
- `just build-windows` still provides the fast cross-build.
- `just check` still works without Windows inputs or KVM.
- The base image can be built unattended from hash-verified local inputs.
- `just test-windows-vm` builds and tests the actual dirty working tree as the
  standard `winvm` user.
- The full unit suite and all tests named `TestTorOffline*` pass with the pinned
  Windows Tor bundle.
- A missing Tor executable or skipped offline test makes the VM command fail.
- The Windows process and ACL tests run in both the VM and hosted Windows CI.
- Success, test failure, timeout, signal, and guest-crash paths have bounded
  cleanup and preserve useful logs.
- A successful run leaves no overlay, QEMU process, socket, or forwarded port.
- No Windows media, VM disk, SSH private key, generated credential, or local
  path is tracked by Git.
- The README explains first-time setup, daily use, cache updates, failure
  recovery, licensing, and the difference between the cross-build, VM gate,
  hosted CI, and optional public-network test.

## 16. Deliberate differences from the source brief

The older `local/AGENT_WINDOWS_TEST_HARNESS_SETUP.md` targets projects that
load a Windows split-tunnel driver. This repository is a pure-Go Tor process
and control-protocol library. Therefore this plan removes:

- the OCI runner and Docker or Podman engine;
- Wintun and Mullvad driver packages;
- driver signing, WDK, test certificates, and test-signing mode;
- TAP, bridge, router, DNS, packet-capture, and `NET_ADMIN` requirements;
- cgo and MinGW requirements;
- TPM, Secure Boot, and HVCI test matrices from the first version;
- privileged integration-test profiles and driver cleanup logic;
- the requirement that the normal `just test` command boot a Windows VM.

These items can be added later only if this repository gains code that needs
them. They are not prerequisites for testing its current Windows behavior.
