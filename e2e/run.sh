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
