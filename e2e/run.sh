#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=tor-driver-e2e:local
platform=${TOR_DRIVER_E2E_PLATFORM:-linux/amd64}
test_pattern='^TestTorPrivate'
run_containment=1

if (($# > 1)); then
    echo "usage: $0 [--smoke]" >&2
    exit 2
fi

case ${1:-} in
    "") ;;
    --smoke)
        test_pattern='^(TestTorPrivateDirectExitAndOutboundReplacement|TestTorPrivateObfs4Exit)$'
        run_containment=0
        ;;
    *)
        echo "usage: $0 [--smoke]" >&2
        exit 2
        ;;
esac

docker build --platform "$platform" --file "$root/e2e/Dockerfile" --tag "$image" "$root"
docker run \
    --env "TOR_DRIVER_E2E_TEST_PATTERN=$test_pattern" \
    --init \
    --network none \
    --platform "$platform" \
    --rm \
    --tmpfs /tmp:rw,exec,nosuid,size=512m \
    "$image"

if ((!run_containment)); then
    exit 0
fi

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
    test -race -count=1 -tags=e2e -run '^(TestTorLinuxLaunchClearsAmbientCapabilities|TestTorContainedTransportSocketDenial|TestTorContainedRejectsEscapableDelegation|TestTorContainedRejectsRootDelegationWritableByChild|TestTorBestEffortEnvironment)$' -v -timeout 3m .
