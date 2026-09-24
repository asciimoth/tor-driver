#!/usr/bin/env bash
set -euo pipefail

winvm_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$winvm_dir/../.." && pwd -P)
config_file="$winvm_dir/config.json"
lock_file="$winvm_dir/image-lock.json"

if [[ -f "${WINVM_ENV_FILE:-$winvm_dir/env}" ]]; then
    set -a
    # This machine-local file is trusted configuration and is not committed.
    # shellcheck disable=SC1090
    source "${WINVM_ENV_FILE:-$winvm_dir/env}"
    set +a
fi

winvm_cache_dir=${WINVM_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/tor-driver/winvm}

ensure_cache_dir() {
    mkdir -p -- "$winvm_cache_dir"
    chmod 0700 "$winvm_cache_dir"
}

die() {
    printf 'winvm: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing command '$1'; enter 'nix develop'"
}

sha256_file() {
    sha256sum -- "$1" | awk '{print $1}'
}

locked_value() {
    jq -er "$1" "$lock_file"
}

input_path() {
    local section=$1
    local environment value
    environment=$(locked_value ".${section}.environment")
    value=${!environment:-}
    [[ -n "$value" ]] || die "$environment is not set; copy dev/winvm/env.example to dev/winvm/env"
    [[ "$value" = /* ]] || die "$environment must be an absolute path"
    printf '%s\n' "$value"
}

package_path() {
    local section=$1
    printf '%s/inputs/%s\n' "$winvm_cache_dir" "$(locked_value ".${section}.file")"
}

verify_hash() {
    local label=$1 path=$2 expected=$3
    [[ -f "$path" ]] || die "$label is absent: $path"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "$label has no reviewed SHA-256 in dev/winvm/image-lock.json"
    local actual
    actual=$(sha256_file "$path")
    [[ "$actual" == "$expected" ]] || die "$label SHA-256 mismatch: expected $expected, got $actual"
}

download_packages() {
    require_command curl
    require_command jq
    require_command sha256sum
    ensure_cache_dir
    mkdir -p -- "$winvm_cache_dir/inputs"
    chmod 0700 "$winvm_cache_dir/inputs"
    local section path source expected partial actual
    for section in go tor openssh; do
        path=$(package_path "$section")
        source=$(locked_value ".${section}.source")
        expected=$(locked_value ".${section}.sha256")
        if [[ -f "$path" ]] && [[ $(sha256_file "$path") == "$expected" ]]; then
            continue
        fi
        partial="$path.partial.$$"
        printf 'Downloading %s from its locked URL...\n' "$section"
        curl --fail --location --proto '=https' --tlsv1.2 --output "$partial" "$source"
        actual=$(sha256_file "$partial")
        if [[ "$actual" != "$expected" ]]; then
            printf 'winvm: %s download SHA-256 mismatch: expected %s, got %s\n' "$section" "$expected" "$actual" >&2
            return 1
        fi
        mv -- "$partial" "$path"
    done
}

find_ovmf() {
    local kind=$1 override candidate
    if [[ "$kind" == code ]]; then
        override=${WINVM_OVMF_CODE:-}
        candidates=(
            /run/current-system/sw/share/qemu/edk2-x86_64-code.fd
            /run/current-system/sw/share/edk2/x64/OVMF_CODE.fd
            /usr/share/OVMF/OVMF_CODE_4M.fd
            /usr/share/OVMF/OVMF_CODE.fd
        )
    else
        override=${WINVM_OVMF_VARS:-}
        candidates=(
            /run/current-system/sw/share/qemu/edk2-i386-vars.fd
            /run/current-system/sw/share/edk2/x64/OVMF_VARS.fd
            /usr/share/OVMF/OVMF_VARS_4M.fd
            /usr/share/OVMF/OVMF_VARS.fd
        )
    fi
    if [[ -n "$override" && -f "$override" ]]; then
        printf '%s\n' "$override"
        return
    fi
    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    return 1
}

base_key() {
    local qemu_version ovmf_code ovmf_vars input
    local -a key_files
    qemu_version=$(qemu-system-x86_64 --version | head -n 1)
    ovmf_code=$(find_ovmf code) || die "OVMF code firmware is absent; enter 'nix develop' or set WINVM_OVMF_CODE"
    ovmf_vars=$(find_ovmf vars) || die "OVMF variable firmware is absent; enter 'nix develop' or set WINVM_OVMF_VARS"
    key_files=(
        "$config_file"
        "$lock_file"
        "$winvm_dir/Autounattend.xml"
        "$winvm_dir/provision.ps1"
        "$winvm_dir/common.sh"
        "$winvm_dir/build-image.sh"
        "$winvm_dir/tools/qga.py"
        "$repo_root/flake.lock"
    )
    for input in "$ovmf_code" "$ovmf_vars" "${key_files[@]}"; do
        [[ -f "$input" ]] || die "base-image key input is absent: $input"
    done
    {
        printf '%s\n' "$qemu_version"
        printf '%s\n' 'machine=q35,accel=kvm;disk=ahci;net=e1000e;firmware=ovmf'
        sha256_file "$ovmf_code"
        sha256_file "$ovmf_vars"
        for input in "${key_files[@]}"; do
            sha256_file "$input"
        done
    } | sha256sum | awk '{print $1}'
}

allocate_port() {
    python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

allocate_locked_port() {
    local minimum maximum span offset candidate candidate_fd attempt
    minimum=$(jq -r '.ssh.portMinimum' "$config_file")
    maximum=$(jq -r '.ssh.portMaximum' "$config_file")
    span=$((maximum - minimum + 1))
    mkdir -p -- "$winvm_cache_dir/locks/ports"
    for ((attempt = 0; attempt < span; attempt++)); do
        offset=$(((RANDOM + attempt) % span))
        candidate=$((minimum + offset))
        exec {candidate_fd}>"$winvm_cache_dir/locks/ports/$candidate.lock"
        if flock -n "$candidate_fd" && python3 - "$candidate" <<'PY'; then
import socket
import sys
port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", port))
PY
            # These globals return the allocation and keep its lock descriptor open.
            # shellcheck disable=SC2034
            winvm_ssh_port=$candidate
            # shellcheck disable=SC2034
            winvm_port_lock_fd=$candidate_fd
            return 0
        fi
        exec {candidate_fd}>&-
    done
    die "no unused SSH port is available in the configured range"
}

wait_for_pid() {
    local pid=$1 timeout_seconds=$2
    local end=$((SECONDS + timeout_seconds)) state
    while kill -0 "$pid" 2>/dev/null; do
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
        [[ "$state" == Z ]] && return 0
        ((SECONDS < end)) || return 1
        sleep 1
    done
}

stop_and_reap_pid() {
    local pid=$1 initial_timeout=$2 term_timeout=$3 kill_timeout=$4
    if ! wait_for_pid "$pid" "$initial_timeout"; then
        kill -TERM "$pid" 2>/dev/null || true
        if ! wait_for_pid "$pid" "$term_timeout"; then
            kill -KILL "$pid" 2>/dev/null || true
            wait_for_pid "$pid" "$kill_timeout" || return 1
        fi
    fi
    wait "$pid" 2>/dev/null || true
}

make_socket_dir() {
    local runtime_root candidate socket_suffix=/qga.sock
    runtime_root=${XDG_RUNTIME_DIR:-/tmp}
    if [[ "$runtime_root" != /* || ! -d "$runtime_root" || ! -w "$runtime_root" ]]; then
        runtime_root=/tmp
    fi
    candidate=$(mktemp -d "$runtime_root/tor-driver-winvm.XXXXXX")
    if ((${#candidate} + ${#socket_suffix} >= 108)); then
        find "$candidate" -depth -delete
        candidate=$(mktemp -d /tmp/tor-driver-winvm.XXXXXX)
    fi
    ((${#candidate} + ${#socket_suffix} < 108)) || die "cannot create a short QEMU socket path"
    chmod 0700 "$candidate"
    printf '%s\n' "$candidate"
}

remove_socket_dir() {
    local socket_dir=$1
    [[ -n "$socket_dir" && ${socket_dir##*/} == tor-driver-winvm.* ]] || die "refusing unexpected socket directory: $socket_dir"
    [[ ! -e "$socket_dir" ]] || find "$socket_dir" -depth -delete
}
