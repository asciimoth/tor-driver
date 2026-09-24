#!/usr/bin/env bash
# shellcheck disable=SC2029
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=common.sh
source "$script_dir/common.sh"

mode=baseline
shell_run=''
case "${1:-}" in
    --public) mode=public ;;
    --shell)
        mode=shell
        shell_run=${2:-}
        [[ -n "$shell_run" ]] || die "usage: run.sh --shell .artifacts/winvm/run-ID"
        ;;
    --clean) mode=clean ;;
    '') ;;
    *) die "unknown option: $1" ;;
esac

artifact_setting=$(jq -r '.artifacts.directory' "$config_file")
artifact_root=$(realpath -m "$repo_root/$artifact_setting")
expected_artifact_root="$repo_root/.artifacts/winvm"
[[ "$artifact_root" == "$expected_artifact_root" ]] || die "refusing unexpected artifact root: $artifact_root"

if [[ "$mode" == clean ]]; then
    if [[ ! -d "$artifact_root" ]]; then
        printf 'No Windows VM run artifacts exist.\n'
        exit 0
    fi
    while IFS= read -r -d '' target; do
        resolved=$(realpath -e "$target")
        [[ "$resolved" == "$artifact_root"/run-* ]] || die "refusing unexpected cleanup target: $resolved"
        find "$resolved" -depth -delete
    done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d -name 'run-*' -print0)
    printf 'Removed validated Windows VM run artifacts from %s. The base image was kept.\n' "$artifact_root"
    exit 0
fi

for command in qemu-system-x86_64 qemu-img ssh scp jq python3 timeout flock git tar; do
    require_command "$command"
done
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is not accessible; run 'just winvm-doctor'"

if [[ "$mode" == shell ]]; then
    run_dir=$(realpath -e "$shell_run") || die "retained run directory does not exist: $shell_run"
    [[ "$run_dir" == "$artifact_root"/run-* ]] || die "refusing retained run outside $artifact_root"
    key=$(jq -er '.baseImageKey' "$run_dir/run.json") || die "retained run has no base-image key"
else
    key=$(base_key)
fi
image_dir="$winvm_cache_dir/images/$key"
base_image="$image_dir/base.qcow2"
manifest="$image_dir/manifest.json"
host_key="$image_dir/host-key.pub"
base_vars="$image_dir/OVMF_VARS.fd"
ssh_key="$winvm_cache_dir/ssh/id_ed25519"
for path in "$base_image" "$base_vars" "$manifest" "$host_key" "$ssh_key"; do
    [[ -r "$path" ]] || die "base image input is absent: $path; run 'just winvm-image'"
done
backing=$(qemu-img info --output=json "$base_image" | jq -r '.format')
[[ "$backing" == qcow2 ]] || die "base image format is not qcow2"

ensure_cache_dir
mkdir -p -- "$artifact_root" "$winvm_cache_dir/locks"
chmod 0700 "$artifact_root" "$winvm_cache_dir/locks"
exec 8>"$winvm_cache_dir/locks/image-$key.lock"
flock -s 8

if [[ "$mode" == shell ]]; then
    overlay="$run_dir/overlay.qcow2"
    [[ -f "$overlay" ]] || die "retained overlay is absent: $overlay"
else
    run_id="run-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
    run_dir="$artifact_root/$run_id"
    mkdir -m 0700 -- "$run_dir"
    overlay="$run_dir/overlay.qcow2"
fi

socket_dir=$(make_socket_dir)
qga_socket="$socket_dir/qga.sock"
qmp_socket="$socket_dir/qmp.sock"
serial_log="$run_dir/serial.log"
qemu_log="$run_dir/qemu.log"
qga_log="$run_dir/guest-agent.log"
qemu_command_log="$run_dir/qemu-command.log"
if [[ "$mode" == shell ]]; then
    serial_log="$run_dir/shell-serial.log"
    qemu_log="$run_dir/shell-qemu.log"
    qga_log="$run_dir/shell-guest-agent.log"
    qemu_command_log="$run_dir/qemu-shell-command.log"
fi
vars_disk="$run_dir/OVMF_VARS.fd"
qemu_pid=''
witness_pid=''
success=0
stage=setup
failure_stage=''

if [[ "$mode" != shell ]]; then
    revision=$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null || printf unknown)
    if [[ -n $(git -C "$repo_root" status --porcelain=v1) ]]; then dirty=true; else dirty=false; fi
    jq -n \
        --arg revision "$revision" --argjson dirty "$dirty" --arg key "$key" \
        --arg started "$(date -u +%FT%TZ)" --arg mode "$mode" \
        '{revision:$revision,dirty:$dirty,baseImageKey:$key,startedAt:$started,mode:$mode,status:"running",stage:"setup"}' \
        >"$run_dir/run.json"
    cp -- "$manifest" "$run_dir/image-manifest.json"
fi

safe_remove_overlay() {
    [[ "$overlay" == "$artifact_root"/run-*/overlay.qcow2 ]] || die "refusing unexpected overlay path: $overlay"
    [[ ! -e "$overlay" ]] || rm -- "$overlay"
}

stop_qemu() {
    [[ -n "$qemu_pid" ]] || return 0
    if kill -0 "$qemu_pid" 2>/dev/null; then
        printf '%s shutdown request\n' "$(date -u +%FT%TZ)" >>"$qga_log"
        "$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 5 shutdown >>"$qga_log" 2>&1 || true
        if ! wait_for_pid "$qemu_pid" "$(jq -r '.machine.shutdownTimeoutSeconds' "$config_file")"; then
            "$script_dir/tools/qga.py" --socket "$qmp_socket" --timeout 5 qmp quit >>"$qga_log" 2>&1 || true
        fi
        if ! stop_and_reap_pid "$qemu_pid" 10 10 10; then
            printf '%s QEMU PID %s remains after SIGKILL\n' "$(date -u +%FT%TZ)" "$qemu_pid" >>"$qga_log"
        fi
    else
        wait "$qemu_pid" 2>/dev/null || true
    fi
    qemu_pid=''
}

cleanup() {
    local status=$?
    local recorded_stage=${failure_stage:-$stage}
    trap - EXIT INT TERM
    if [[ -n "$witness_pid" ]]; then
        stop_and_reap_pid "$witness_pid" 2 2 2 || true
        witness_pid=''
    fi
    stop_qemu
    remove_socket_dir "$socket_dir"
    if [[ -n ${payload:-} && "$payload" == "$run_dir/worktree.tar" && -f "$payload" ]]; then
        find "$payload" -maxdepth 0 -type f -delete
    fi
    if [[ "$mode" != shell && -f "$run_dir/run.json" ]]; then
        jq --arg status "$status" --arg stage "$recorded_stage" --arg finished "$(date -u +%FT%TZ)" \
            '.status = (if $status == "0" then "passed" else "failed" end) | .exitStatus = ($status|tonumber) | .stage=$stage | .finishedAt=$finished' \
            "$run_dir/run.json" >"$run_dir/run.json.final" 2>/dev/null &&
            mv -- "$run_dir/run.json.final" "$run_dir/run.json" || true
    fi
    if (( success == 1 )); then
        safe_remove_overlay
        find "$run_dir" -maxdepth 1 -name 'OVMF_VARS.fd' -type f -delete
    else
        printf '%s\n' "$recorded_stage" >"$run_dir/failure-stage.txt"
        if [[ $(jq -r '.artifacts.retainFailedOverlay' "$config_file") == true && -f "$overlay" ]]; then
            printf 'Retained failed overlay. Diagnose it with:\n  just winvm-shell %q\n' "$run_dir" >&2
        else
            safe_remove_overlay
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$mode" != shell ]]; then
    qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$overlay"
fi
overlay_info=$(qemu-img info --backing-chain --output=json "$overlay")
actual_backing=$(jq -r '.[0]["backing-filename"] // empty' <<<"$overlay_info")
[[ -n "$actual_backing" ]] || die "overlay has no backing file"
[[ $(realpath -e "$actual_backing") == "$(realpath -e "$base_image")" ]] || die "overlay has an unexpected backing file: $actual_backing"
cp -- "$base_vars" "$vars_disk"
chmod 0600 "$vars_disk"

allocate_locked_port
ssh_port=$winvm_ssh_port
known_hosts="$run_dir/known_hosts"
read -r host_key_type host_key_data <"$host_key"
printf '[127.0.0.1]:%s %s %s\n' "$ssh_port" "$host_key_type" "$host_key_data" >"$known_hosts"
cpus=$(jq -r '.machine.cpus' "$config_file")
memory=$(jq -r '.machine.memoryMiB' "$config_file")
qemu_command=(
    qemu-system-x86_64
    -name tor-driver-winvm-test
    -machine "$(jq -r '.machine.type' "$config_file")"
    -cpu host -smp "$cpus" -m "$memory"
    -no-reboot -display none
    -chardev "file,id=serial0,path=$serial_log" -serial chardev:serial0
    -drive "if=pflash,format=raw,readonly=on,file=$(find_ovmf code)"
    -drive "if=pflash,format=raw,file=$vars_disk"
    -device "ich9-ahci,id=sata"
    -drive "if=none,id=osdisk,format=qcow2,file=$overlay,cache=writeback" -device "ide-hd,drive=osdisk,bus=sata.0"
    -device "e1000e,netdev=net0"
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
    -device virtio-serial-pci
    -chardev "socket,path=$qga_socket,server=on,wait=off,id=qga0"
    -device "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
    -qmp "unix:$qmp_socket,server=on,wait=off"
)
{
    printf 'base_image_key=%s\n' "$key"
    printf 'ssh_forward=127.0.0.1:%s\n' "$ssh_port"
    printf 'qemu='; printf '%q ' "${qemu_command[@]}"; printf '\n'
} >"$qemu_command_log"
"${qemu_command[@]}" >>"$qemu_log" 2>&1 &
qemu_pid=$!

ssh_options=(
    -i "$ssh_key"
    -p "$ssh_port"
    -o BatchMode=yes
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$known_hosts"
    -o ConnectTimeout=5
)
scp_options=(
    -i "$ssh_key"
    -P "$ssh_port"
    -o BatchMode=yes
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$known_hosts"
    -o ConnectTimeout=5
)
ssh_target="$(jq -r '.ssh.user' "$config_file")@127.0.0.1"

stage=boot
boot_timeout=$(jq -r '.machine.bootTimeoutSeconds' "$config_file")
deadline=$((SECONDS + boot_timeout))
qga_ready=0
ssh_ready=0
while (( SECONDS < deadline )); do
    kill -0 "$qemu_pid" 2>/dev/null || die "QEMU exited during $stage; see $qemu_log"
    if (( qga_ready == 0 )) && "$script_dir/tools/qga.py" --socket "$qga_socket" --timeout 5 ping >>"$qga_log" 2>&1; then
        qga_ready=1
    fi
    if (( ssh_ready == 0 )) && ssh "${ssh_options[@]}" "$ssh_target" 'cmd.exe /c exit 0' >/dev/null 2>&1; then
        ssh_ready=1
    fi
    (( qga_ready == 1 && ssh_ready == 1 )) && break
    sleep 2
done
(( qga_ready == 1 )) || die "QEMU Guest Agent did not become ready in ${boot_timeout}s"
(( ssh_ready == 1 )) || die "SSH authentication did not become ready in ${boot_timeout}s"

if [[ "$mode" == shell ]]; then
    stage=shell
    printf 'Opening the retained VM as the standard winvm account.\n'
    ssh "${ssh_options[@]}" -t "$ssh_target" 'powershell.exe -NoLogo'
    stop_qemu
    remove_socket_dir "$socket_dir"
    trap - EXIT INT TERM
    exit 0
fi

stage=package
payload="$run_dir/worktree.tar"
"$script_dir/package-worktree.sh" "$payload" >/dev/null

remote_id=${run_id//[^A-Za-z0-9-]/}
remote_root="C:/winvm/runs/$remote_id"
stage=transfer
ssh "${ssh_options[@]}" "$ssh_target" "powershell.exe -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$remote_root/source','$remote_root/artifacts' | Out-Null\""
scp "${scp_options[@]}" "$payload" "$ssh_target:$remote_root/worktree.tar" >/dev/null
find "$payload" -maxdepth 0 -type f -delete
ssh "${ssh_options[@]}" "$ssh_target" "tar.exe -xf \"$remote_root/worktree.tar\" -C \"$remote_root/source\""

stage='test'
test_timeout=$(jq -r '.machine.testTimeoutSeconds' "$config_file")
public_argument=''
[[ "$mode" == public ]] && public_argument=' -PublicOnly'
remote_test="Set-Location '$remote_root/source'; & './dev/winvm/test.ps1' -ArtifactDir '$remote_root/artifacts' -ImageManifest 'C:/winvm/manifest.json'$public_argument"
set +e
timeout --foreground --signal=TERM --kill-after=30 "${test_timeout}s" \
    ssh "${ssh_options[@]}" "$ssh_target" "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command \"$remote_test\"" \
    2>&1 | tee "$run_dir/windows-console.log"
test_status=${PIPESTATUS[0]}
set -e

if (( test_status == 0 )) && [[ "$mode" == baseline ]]; then
    stage='containment-test'
    witness_ready="$socket_dir/network-witness.json"
    python3 "$script_dir/tools/network-witness.py" "$witness_ready" >"$run_dir/network-witness.log" 2>&1 &
    witness_pid=$!
    for _ in {1..100}; do
        [[ -s "$witness_ready" ]] && break
        kill -0 "$witness_pid" 2>/dev/null || die "network witness exited; see $run_dir/network-witness.log"
        sleep 0.05
    done
    [[ -s "$witness_ready" ]] || die "network witness did not become ready"
    probe_ipv4="10.0.2.2:$(jq -er '.tcp4' "$witness_ready")"
    probe_ipv6="[fec0::2]:$(jq -er '.tcp6' "$witness_ready")"
    probe_udp="10.0.2.2:$(jq -er '.udp4' "$witness_ready")"
    containment_command="Set-Location '$remote_root/source'; & './dev/winvm/containment.ps1' -ArtifactDir '$remote_root/artifacts' -IPv4Probe '$probe_ipv4' -IPv6Probe '$probe_ipv6' -UDPProbe '$probe_udp'"
    set +e
    timeout --foreground --signal=TERM --kill-after=30 "${test_timeout}s" \
        "$script_dir/tools/qga.py" --socket "$qga_socket" --timeout "$test_timeout" exec \
        powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$containment_command" \
        2>&1 | tee "$run_dir/windows-containment-console.log"
    test_status=${PIPESTATUS[0]}
    set -e
    stop_and_reap_pid "$witness_pid" 2 2 2 || true
    witness_pid=''
    if (( test_status != 0 )); then
        failure_stage='containment-test'
        (( test_status == 124 )) && failure_stage='containment-test-timeout'
    fi
fi

if (( test_status != 0 )); then
    if [[ -z "$failure_stage" ]]; then
        failure_stage='test'
        (( test_status == 124 )) && failure_stage='test-timeout'
    fi
    stage=diagnostics
    diagnostics="Get-Process | Sort-Object ProcessName | Format-Table -AutoSize; Get-CimInstance Win32_LogicalDisk | Format-Table -AutoSize; Get-WinEvent -FilterHashtable @{LogName='Application','System'; StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue | Select-Object -First 100 | Format-List"
    ssh "${ssh_options[@]}" "$ssh_target" "powershell.exe -NoProfile -Command \"$diagnostics\"" >"$run_dir/diagnostics.log" 2>&1 || true
fi

stage=artifacts
ssh "${ssh_options[@]}" "$ssh_target" "tar.exe -cf \"$remote_root/artifacts.tar\" -C \"$remote_root\" artifacts" >/dev/null 2>&1 || true
scp "${scp_options[@]}" "$ssh_target:$remote_root/artifacts.tar" "$run_dir/guest-artifacts.tar" >/dev/null 2>&1 || true
if [[ -f "$run_dir/guest-artifacts.tar" ]]; then
    mkdir -p -- "$run_dir/guest"
    tar -xf "$run_dir/guest-artifacts.tar" -C "$run_dir/guest"
fi

if (( test_status != 0 )); then
    printf 'winvm: Windows test command failed with exit status %s; artifacts: %s\n' "$test_status" "$run_dir" >&2
    exit "$test_status"
fi
stage=shutdown
success=1
printf 'Windows VM tests passed. Artifacts: %s\n' "$run_dir"
