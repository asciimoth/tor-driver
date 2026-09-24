#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=tor-driver-e2e:local
platform=${TOR_DRIVER_E2E_PLATFORM:-linux/amd64}

docker build --platform "$platform" --file "$root/e2e/Dockerfile" --tag "$image" "$root"
docker run \
    --init \
    --network none \
    --platform "$platform" \
    --rm \
    --tmpfs /tmp:rw,exec,nosuid,size=512m \
    "$image"

# This profile confirms the deployable per-process firewall. The container has
# a normal parent network, while Tor and its PT run in a filtered cgroup.
docker run \
    --cgroupns host \
    --entrypoint go \
    --platform "$platform" \
    --privileged \
    --rm \
    --tmpfs /tmp:rw,exec,nosuid,size=512m \
    --user root \
    "$image" \
    test -race -count=1 -tags=e2e -run '^(TestTorContainedTransportSocketDenial|TestTorBestEffortEnvironment)$' -v -timeout 3m .
