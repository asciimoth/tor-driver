#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"

download_packages
"$script_dir/doctor.sh"

key=$(base_key)
image_dir="$winvm_cache_dir/images/$key"
base_image="$image_dir/base.qcow2"
manifest_path="$image_dir/manifest.json"
ssh_key="$winvm_cache_dir/ssh/id_ed25519"
mkdir -p -- "$winvm_cache_dir/images" "$winvm_cache_dir/locks" "$winvm_cache_dir/ssh"
chmod 0700 "$winvm_cache_dir/images" "$winvm_cache_dir/locks" "$winvm_cache_dir/ssh"

exec 9>"$winvm_cache_dir/locks/image-$key.lock"
printf 'Waiting for the base-image lock...\n'
flock 9
if [[ -r "$base_image" && -r "$image_dir/OVMF_VARS.fd" && -r "$manifest_path" && -r "$image_dir/host-key.pub" ]]; then
    [[ -r "$ssh_key" ]] || die "the base image SSH private key is absent; remove this base-image directory and rebuild it"
    printf 'Reusing Windows base image %s\n' "$key"
    exit 0
fi

work_dir=$(mktemp -d "$winvm_cache_dir/build-$key.XXXXXX")
socket_dir=$(make_socket_dir)
disk="$work_dir/base.qcow2"
answer="$work_dir/Autounattend.xml"
provision="$work_dir/provision.ps1"
answer_iso="$work_dir/provision.iso"
qga_socket="$socket_dir/qga.sock"
qmp_socket="$socket_dir/qmp.sock"
serial_log="$work_dir/serial.log"
vars_disk="$work_dir/OVMF_VARS.fd"
qemu_pid=''

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        "$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 5 shutdown >/dev/null 2>&1 || true
        if ! stop_and_reap_pid "$qemu_pid" 20 10 10; then
            printf 'winvm: QEMU did not exit after SIGKILL; PID %s remains\n' "$qemu_pid" >&2
        fi
    elif [[ -n "$qemu_pid" ]]; then
        wait "$qemu_pid" 2>/dev/null || true
    fi
    remove_socket_dir "$socket_dir"
    if ((status != 0)); then
        printf 'winvm: image build failed; installation files remain in %s\n' "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ ! -f "$ssh_key" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C 'tor-driver winvm' -f "$ssh_key"
    chmod 0600 "$ssh_key"
fi

admin_password=$(python3 -c 'import secrets; print(secrets.token_hex(24) + "aA!")')
windows_name=$(jq -r '.windowsImageName' "$config_file")
cp -- "$script_dir/Autounattend.xml" "$answer"
sed -i \
    -e "s|@@WINDOWS_IMAGE_NAME@@|$windows_name|g" \
    -e "s|@@ADMIN_PASSWORD@@|$admin_password|g" \
    "$answer"
unset admin_password

cp -- "$script_dir/provision.ps1" "$provision"
sed -i \
    -e "s|@@GO_FILE@@|$(locked_value '.go.file')|g" \
    -e "s|@@GO_VERSION@@|$(locked_value '.go.version')|g" \
    -e "s|@@TOR_FILE@@|$(locked_value '.tor.file')|g" \
    -e "s|@@TOR_VERSION@@|$(locked_value '.tor.version')|g" \
    -e "s|@@OPENSSH_FILE@@|$(locked_value '.openssh.file')|g" \
    "$provision"
cp -- "$ssh_key.pub" "$work_dir/authorized_key.pub"
for section in go tor openssh; do
    cp -- "$(package_path "$section")" "$work_dir/"
done

xorriso -as mkisofs -quiet -J -R -V WINVM_PROVISION -o "$answer_iso" \
    "$answer" "$provision" "$work_dir/authorized_key.pub" \
    "$work_dir/$(locked_value '.go.file')" \
    "$work_dir/$(locked_value '.tor.file')" \
    "$work_dir/$(locked_value '.openssh.file')"

disk_gib=$(jq -r '.machine.diskGiB' "$config_file")
cpus=$(jq -r '.machine.cpus' "$config_file")
memory=$(jq -r '.machine.memoryMiB' "$config_file")
install_timeout=$(jq -r '.machine.installTimeoutSeconds' "$config_file")
allocate_locked_port
ssh_port=$winvm_ssh_port
qemu-img create -q -f qcow2 "$disk" "${disk_gib}G"
cp -- "$(find_ovmf vars)" "$vars_disk"
chmod 0600 "$vars_disk"

qemu_command=(
    qemu-system-x86_64
    -name tor-driver-winvm-build
    -machine "$(jq -r '.machine.type' "$config_file")"
    -cpu host -smp "$cpus" -m "$memory"
    -display none
    -chardev "file,id=serial0,path=$serial_log" -serial chardev:serial0
    -drive "if=pflash,format=raw,readonly=on,file=$(find_ovmf code)"
    -drive "if=pflash,format=raw,file=$vars_disk"
    -device "ich9-ahci,id=sata"
    -drive "if=none,id=osdisk,format=qcow2,file=$disk,cache=writeback" -device "ide-hd,drive=osdisk,bus=sata.0"
    -drive "if=none,id=windows,media=cdrom,readonly=on,file=$(input_path windows)" -device "ide-cd,drive=windows,bus=sata.1"
    -drive "if=none,id=virtio,media=cdrom,readonly=on,file=$(input_path virtio)" -device "ide-cd,drive=virtio,bus=sata.2"
    -drive "if=none,id=provision,media=cdrom,readonly=on,file=$answer_iso" -device "ide-cd,drive=provision,bus=sata.3"
    -device "e1000e,netdev=net0"
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
    -device virtio-serial-pci
    -chardev "socket,path=$qga_socket,server=on,wait=off,id=qga0"
    -device "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
    -qmp "unix:$qmp_socket,server=on,wait=off"
    -boot "once=d,menu=off"
)
printf '%q ' "${qemu_command[@]}" >"$work_dir/qemu-command.log"
printf '\n' >>"$work_dir/qemu-command.log"
"${qemu_command[@]}" &
qemu_pid=$!

# Microsoft installation media requires a key press before it starts. Send a
# harmless key during the firmware boot window because this VM is headless.
qmp_deadline=$((SECONDS + 20))
while [[ ! -S "$qmp_socket" && $SECONDS -lt $qmp_deadline ]]; do
    kill -0 "$qemu_pid" 2>/dev/null || die "QEMU exited before its monitor became ready; see $serial_log"
    sleep 0.1
done
[[ -S "$qmp_socket" ]] || die "QEMU monitor did not become ready; see $serial_log"
for _ in {1..12}; do
    "$script_dir/tools/qga.py" --socket "$qmp_socket" --timeout 5 qmp send-key \
        --arguments '{"keys":[{"type":"qcode","data":"spc"}]}' >/dev/null
    sleep 1
done

deadline=$((SECONDS + install_timeout))
printf 'Installing and provisioning Windows. This can take up to %s minutes.\n' "$((install_timeout / 60))"
while ((SECONDS < deadline)); do
    kill -0 "$qemu_pid" 2>/dev/null || die "QEMU exited during Windows installation; see $serial_log"
    if "$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 5 ping >/dev/null 2>&1 &&
        "$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 20 exec powershell.exe -NoProfile -Command "if (Test-Path C:\\winvm\\ready) { exit 0 } else { exit 1 }" >/dev/null 2>&1; then
        break
    fi
    sleep 5
done
((SECONDS < deadline)) || die "Windows installation exceeded its timeout; see $serial_log"

guest_manifest="$work_dir/guest-manifest.json"
"$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 30 exec powershell.exe -NoProfile -Command "Get-Content -Raw C:\\winvm\\manifest.json" >"$guest_manifest"
jq -e . "$guest_manifest" >/dev/null || die "guest image manifest is invalid"

known_hosts="$work_dir/known_hosts.scan"
ssh_deadline=$((SECONDS + 120))
while ((SECONDS < ssh_deadline)); do
    if ssh-keyscan -T 5 -p "$ssh_port" 127.0.0.1 >"$known_hosts" 2>/dev/null && [[ -s "$known_hosts" ]]; then
        break
    fi
    sleep 2
done
[[ -s "$known_hosts" ]] || die "cannot record the guest SSH host key"
host_key="$work_dir/host-key.pub"
awk '$2 == "ssh-ed25519" {print $2, $3; exit}' "$known_hosts" >"$host_key"
[[ -s "$host_key" ]] || die "the guest has no Ed25519 SSH host key"
ssh -i "$ssh_key" -p "$ssh_port" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known_hosts" -o ConnectTimeout=10 \
    winvm@127.0.0.1 'powershell.exe -NoProfile -Command "if (-not (Test-Path C:\winvm\ready)) { exit 1 }; go version; & C:\winvm\Tor\tor\tor.exe --version"' \
    >"$work_dir/guest-self-check.log"

"$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 10 shutdown || true
wait_for_pid "$qemu_pid" "$(jq -r '.machine.shutdownTimeoutSeconds' "$config_file")" || die "guest did not shut down after provisioning"
wait "$qemu_pid" || true
qemu_pid=''

mkdir -p -- "$image_dir"
mv -- "$disk" "$base_image"
mv -- "$vars_disk" "$image_dir/OVMF_VARS.fd"
jq -n --arg key "$key" --argjson guest "$(cat "$guest_manifest")" \
    --arg sshHostKeyFingerprint "$(ssh-keygen -lf "$host_key" | awk '{print $2}')" \
    '{baseImageKey: $key, sshHostKeyFingerprint: $sshHostKeyFingerprint} + $guest' >"$manifest_path"
mv -- "$host_key" "$image_dir/host-key.pub"
ssh-keygen -lf "$image_dir/host-key.pub" >"$image_dir/host-key.fingerprint"
chmod 0444 "$base_image" "$image_dir/OVMF_VARS.fd" "$manifest_path" "$image_dir/host-key.pub" "$image_dir/host-key.fingerprint"
[[ "$work_dir" == "$winvm_cache_dir"/build-"$key".* ]] || die "refusing unexpected successful build directory: $work_dir"
find "$work_dir" -depth -delete
printf 'Built Windows base image %s\n' "$key"
