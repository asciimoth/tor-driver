#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/../.." && pwd -P)
output=${1:-}
[[ -n "$output" ]] || { printf 'usage: %s OUTPUT.tar\n' "$0" >&2; exit 2; }
[[ "$output" = /* ]] || output="$PWD/$output"
mkdir -p -- "$(dirname -- "$output")"

list=$(mktemp)
cleanup() { rm -f -- "$list"; }
trap cleanup EXIT

cd -- "$repo_root"
git ls-files --deduplicate --cached --modified --others --exclude-standard -z |
    while IFS= read -r -d '' path; do
        [[ -f "$path" || -L "$path" ]] || continue
        case "$path" in
            .git/*|.artifacts/winvm/*|dev/winvm/env|dev/winvm/*.qcow2|dev/winvm/*.sock|dev/winvm/*.iso|dev/winvm/*-payload.tar)
                continue
                ;;
        esac
        printf '%s\0' "$path"
    done >"$list"

tar --null --no-recursion --format=posix --create --file="$output" --files-from="$list"
printf '%s\n' "$output"
