# Native Windows VM tests

This harness builds and tests the current working tree in a disposable Windows
Server 2022 amd64 VM. It uses QEMU/KVM directly on Linux. It does not use a
container or a public Tor connection for its default test.

The developer must supply a Windows Server 2022 installation ISO and comply
with its license. The repository does not contain Windows media, product keys,
VM disks, or SSH private keys. The locked input is the Microsoft Windows Server
2022 Standard Evaluation Server Core image. It does not require a purchased
product key. The evaluation expires after 180 days and requires online
activation during its first 10 days.

## Test layers

Use the least costly gate that gives the required evidence:

| Gate | Command | Evidence |
| --- | --- | --- |
| Cross-build | `just build-windows` | All Go packages compile for `windows/amd64`; no Windows code runs. |
| Local VM | `just test-windows-vm` | The dirty working tree runs as the standard `winvm` user on Windows Server 2022. |
| Hosted CI | `windows-baseline` job | The committed revision runs on the GitHub `windows-2022` image. This remains a separate required gate. |
| Public VM | `just test-windows-vm-public` | The explicit public onion test runs in a new VM overlay. |

`just check` does not start a VM. It does not require KVM, Windows media, or a
Windows license.

## First-time setup

1. Enter the pinned development shell:

   ```sh
   nix develop
   ```

2. Obtain the Windows Server 2022 Evaluation amd64 installation ISO and the
   VirtIO ISO named in `image-lock.json`. Copy `env.example` to
   `dev/winvm/env`, then set both absolute ISO paths. The local environment file
   is ignored by Git.

3. Print the ISO hashes:

   ```sh
   just winvm-input-hashes
   ```

   Compare the output with the locked hashes in `image-lock.json`. Do not use
   media when its hash does not match.

4. Check the host and build the base image:

   ```sh
   just winvm-image
   ```

   The build downloads only the Go, Tor, and portable OpenSSH files at the
   locked HTTPS URLs. It checks every file hash before QEMU starts. Installation
   is unattended. No product key is required by the answer file.

The image builder creates a dedicated standard `winvm` account and a private
SSH key in the host cache. It installs signed VirtIO drivers, QEMU Guest Agent,
Go, Tor, and OpenSSH. It records the Windows build, architecture, Go version,
Tor version, Guest Agent version, and SSH host-key fingerprint next to the base
image. The base qcow2 file is read-only.

Provisioning has two phases. Windows Setup stages the locked files and creates
a delayed SYSTEM startup task. The task installs the tools after Windows Setup
releases the Windows Installer service, then removes itself and the staged
files.

The evaluation guest uses QEMU user-mode networking. This permits Windows
activation without exposing an inbound host interface. Replace the base image
before its evaluation period expires.

## Daily use

Run the offline Windows gate:

```sh
just test-windows-vm
```

The command packages tracked files, modifications, and eligible untracked
files. It omits Git-ignored files, VM data, artifacts, sockets, and the local
environment file. It creates a new qcow2 overlay, requires both Guest Agent and
SSH readiness, runs `dev/winvm/test.ps1`, collects artifacts, shuts down the VM,
and removes the successful overlay.

The baseline verifies modules, tidy state, vet for normal and e2e builds, unit
tests, all `TestTorOffline*` tests, and a full build. Structured test events
must contain a pass and no skip for each discovered offline test. The command
also rejects an absent Tor executable, an unexpected Tor version, or a Go
toolchain version that differs from the locked image version.

The public command is an explicit opt-in because it connects to the public Tor
network:

```sh
just test-windows-vm-public
```

It runs only `TestTorOnionHTTPAndOutboundReplacement`. It does not run the
external bridge test or use bridge credentials.

## Artifacts and failure recovery

Each run writes `.artifacts/winvm/run-<id>/`. The directory contains the base
key, revision and dirty status, sanitized QEMU command metadata, image and guest
metadata, serial and console logs, PowerShell logs, structured Go test events,
and the final status. A failed run also tries to collect processes, Tor state,
disk space, and recent Application and System events.

A successful run removes its overlay. A failed run keeps its overlay by
default and prints the exact diagnosis command, for example:

```sh
just winvm-shell .artifacts/winvm/run-20260923T120000Z-1234-5678
```

The shell uses the same standard `winvm` account and verified SSH host key. It
does not disable host-key checks. Remove validated run artifacts and retained
overlays with:

```sh
just winvm-clean
```

This command does not remove the base image. If boot fails, inspect
`serial.log`, `qemu.log`, `guest-agent.log`, and `failure-stage.txt`. If SSH is
unavailable, Guest Agent still requests a bounded shutdown. The harness then
uses QMP and a bounded QEMU process stop.

## Cache and lock updates

The default private cache is
`${XDG_CACHE_HOME:-$HOME/.cache}/tor-driver/winvm`. Set `WINVM_CACHE_DIR` in the
local environment file to use another absolute location. Do not put this cache
in the repository.

Change `image-lock.json` only as a reviewed update. Update source URLs, versions,
and hashes together. The base-image key includes the lock, configuration,
unattended answer file, provisioning and image-build scripts, QEMU machine
definition and version, and `flake.lock`. A relevant change creates a new base
key. It does not change an old image in place.

`just winvm-doctor` checks commands, KVM access, OVMF, media paths and hashes,
downloaded package hashes, available memory, disk space, and loopback port
allocation without starting a VM. Its error messages state the missing input or
host remedy.
