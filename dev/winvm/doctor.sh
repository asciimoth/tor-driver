#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"

mode=${1:-check}

validate_configuration() {
    jq -e '
        .schemaVersion == 1 and
        .architecture == "amd64" and
        (.windowsImageName | type == "string" and length > 0) and
        (.machine.cpus | type == "number" and . >= 2) and
        (.machine.memoryMiB | type == "number" and . >= 4096) and
        (.machine.diskGiB | type == "number" and . >= 40) and
        (.machine.bootTimeoutSeconds | type == "number" and . > 0) and
        (.machine.installTimeoutSeconds | type == "number" and . > 0) and
        (.machine.testTimeoutSeconds | type == "number" and . > 0) and
        (.ssh.user == "winvm") and
        (.ssh.portMinimum | type == "number" and . >= 1024) and
        (.ssh.portMaximum | type == "number") and
        (.ssh.portMaximum >= .ssh.portMinimum) and
        (.artifacts.directory == ".artifacts/winvm") and
        (.test.script == "dev/winvm/test.ps1")
    ' "$config_file" >/dev/null || die "dev/winvm/config.json is invalid"
    jq -e '
        .schemaVersion == 1 and
        ([.windows, .virtio, .go, .tor, .openssh] | all(type == "object")) and
        (.go.version == "1.25.5") and
        (.tor.bundleVersion == "15.0.23") and
        ([.go, .tor, .openssh] | all(.sha256 | test("^[0-9a-f]{64}$")))
    ' "$lock_file" >/dev/null || die "dev/winvm/image-lock.json is invalid"
}

print_input_hashes() {
    validate_configuration
    local section path environment
    for section in windows virtio; do
        environment=$(locked_value ".${section}.environment")
        path=${!environment:-}
        if [[ -z "$path" ]]; then
            printf '%s: not set\n' "$environment"
        elif [[ ! -f "$path" ]]; then
            printf '%s: file not found: %s\n' "$environment" "$path"
        else
            printf '%s %s %s\n' "$(sha256_file "$path")" "$environment" "$path"
        fi
    done
}

case "$mode" in
    --validate)
        validate_configuration
        printf 'Windows VM configuration is valid.\n'
        exit 0
        ;;
    --print-input-hashes)
        print_input_hashes
        exit 0
        ;;
    --base-key)
        validate_configuration
        base_key
        exit 0
        ;;
    check) ;;
    *) die "unknown option: $mode" ;;
esac

for command in qemu-system-x86_64 qemu-img xorriso ssh scp ssh-keygen ssh-keyscan jq python3 curl sha256sum flock git tar; do
    require_command "$command"
done
validate_configuration

[[ $(uname -s) == Linux ]] || die "the Windows VM harness requires a Linux host"
[[ -e /dev/kvm ]] || die "/dev/kvm is absent; enable CPU virtualization and the KVM kernel modules"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is not accessible; add this user to the KVM device group and start a new session"
find_ovmf code >/dev/null || die "OVMF code firmware is absent; enter 'nix develop' or set WINVM_OVMF_CODE"
find_ovmf vars >/dev/null || die "OVMF variable firmware is absent; enter 'nix develop' or set WINVM_OVMF_VARS"

windows_iso=$(input_path windows)
virtio_iso=$(input_path virtio)
verify_hash "Windows installation ISO" "$windows_iso" "$(locked_value '.windows.sha256')"
verify_hash "VirtIO driver ISO" "$virtio_iso" "$(locked_value '.virtio.sha256')"
for section in go tor openssh; do
    [[ -f $(package_path "$section") ]] || die "$section package is not cached; 'just winvm-image' downloads and verifies locked packages"
    verify_hash "$section package" "$(package_path "$section")" "$(locked_value ".${section}.sha256")"
done

memory_mib=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)
required_memory=$(jq -r '.machine.memoryMiB' "$config_file")
((memory_mib >= required_memory)) || die "only ${memory_mib} MiB memory is available; the VM needs ${required_memory} MiB"

ensure_cache_dir
available_kib=$(df -Pk "$winvm_cache_dir" | awk 'NR == 2 {print $4}')
disk_gib=$(jq -r '.machine.diskGiB' "$config_file")
required_kib=$(((disk_gib + 10) * 1024 * 1024))
((available_kib >= required_kib)) || die "the VM cache needs at least $((disk_gib + 10)) GiB free space"

port=$(allocate_port)
[[ "$port" =~ ^[0-9]+$ ]] || die "cannot allocate a loopback SSH port"
printf 'Windows VM host checks passed. A loopback port (%s) is available.\n' "$port"
