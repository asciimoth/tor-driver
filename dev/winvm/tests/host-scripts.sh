#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repo_root=$(cd -- "$script_dir/../.." && pwd -P)
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

"$script_dir/doctor.sh" --validate >/dev/null
jq -e '
    [.windows.sha256, .virtio.sha256] |
    all(test("^[0-9a-f]{64}$"))
' "$script_dir/image-lock.json" >/dev/null
if grep -Eq '(^|[[:space:]])-no-reboot([[:space:]]|$)' "$script_dir/build-image.sh"; then
    printf 'image builder prevents required Windows installation reboots\n' >&2
    exit 1
fi
grep -q '<WillReboot>Always</WillReboot>' "$script_dir/Autounattend.xml" || {
    printf 'unattended setup does not reboot after VirtIO driver installation\n' >&2
    exit 1
}
grep -q '^jq -n --arg key ' "$script_dir/build-image.sh" || {
    printf 'base-image manifest creation can wait for standard input\n' >&2
    exit 1
}

# Missing inputs and checksum mismatches fail closed.
zero_hash=0000000000000000000000000000000000000000000000000000000000000000
if WINVM_CACHE_DIR="$temporary/hash-cache" bash -c "source '$script_dir/common.sh'; verify_hash fixture '$temporary/missing' '$zero_hash'" 2>/dev/null; then
    printf 'missing input was accepted\n' >&2
    exit 1
fi
printf 'content\n' >"$temporary/hash-input"
if WINVM_CACHE_DIR="$temporary/hash-cache" bash -c "source '$script_dir/common.sh'; verify_hash fixture '$temporary/hash-input' '$zero_hash'" 2>/dev/null; then
    printf 'bad input hash was accepted\n' >&2
    exit 1
fi

# The working-tree archive includes tracked changes and eligible untracked files.
fixture="$temporary/package-repo"
mkdir -p "$fixture/dev/winvm"
cp "$script_dir/package-worktree.sh" "$fixture/dev/winvm/"
chmod +x "$fixture/dev/winvm/package-worktree.sh"
git -C "$fixture" init -q
git -C "$fixture" config user.email winvm@example.invalid
git -C "$fixture" config user.name winvm
printf 'original\n' >"$fixture/tracked.txt"
printf 'ignored.txt\ndev/winvm/env\ndev/winvm/tools/__pycache__/\n.artifacts/\n' >"$fixture/.gitignore"
git -C "$fixture" add tracked.txt .gitignore dev/winvm/package-worktree.sh
git -C "$fixture" commit -qm initial
printf 'modified\n' >"$fixture/tracked.txt"
printf 'untracked\n' >"$fixture/untracked.txt"
printf 'secret\n' >"$fixture/ignored.txt"
printf 'WINVM_WINDOWS_ISO=/secret\n' >"$fixture/dev/winvm/env"
mkdir -p "$fixture/dev/winvm/tools/__pycache__"
printf 'bytecode\n' >"$fixture/dev/winvm/tools/__pycache__/qga.pyc"
archive="$temporary/worktree.tar"
(cd "$fixture" && ./dev/winvm/package-worktree.sh "$archive" >/dev/null)
tar -tf "$archive" >"$temporary/archive.list"
grep -qx './tracked.txt\|tracked.txt' "$temporary/archive.list"
grep -qx './untracked.txt\|untracked.txt' "$temporary/archive.list"
[[ $(grep -cx './tracked.txt\|tracked.txt' "$temporary/archive.list") == 1 ]] || {
    printf 'package-worktree.sh included a tracked path more than once\n' >&2
    exit 1
}
if grep -Eq 'ignored\.txt|dev/winvm/env|__pycache__|\.pyc$|\.artifacts' "$temporary/archive.list"; then
    printf 'package-worktree.sh included ignored or private data\n' >&2
    exit 1
fi

# The base key is location independent and changes when a provisioning input changes.
copy="$temporary/key-repo"
mkdir -p "$copy/dev"
cp -R "$script_dir" "$copy/dev/winvm"
cp "$repo_root/flake.lock" "$copy/flake.lock"
first=$(PATH="$PATH" "$copy/dev/winvm/doctor.sh" --base-key)
original=$(PATH="$PATH" "$script_dir/doctor.sh" --base-key)
[[ "$original" == "$first" ]] || { printf 'base key depends on the repository path\n' >&2; exit 1; }
printf '\n# key change fixture\n' >>"$copy/dev/winvm/provision.ps1"
second=$(PATH="$PATH" "$copy/dev/winvm/doctor.sh" --base-key)
[[ "$first" != "$second" ]] || { printf 'base key did not change\n' >&2; exit 1; }

# Concurrent allocators hold different SSH port locks.
WINVM_CACHE_DIR="$temporary/port-cache" bash -c "source '$script_dir/common.sh'; allocate_locked_port; echo \$winvm_ssh_port; sleep 1" >"$temporary/port-one" &
first_port_pid=$!
WINVM_CACHE_DIR="$temporary/port-cache" bash -c "source '$script_dir/common.sh'; allocate_locked_port; echo \$winvm_ssh_port; sleep 1" >"$temporary/port-two" &
second_port_pid=$!
wait "$first_port_pid" "$second_port_pid"
[[ $(cat "$temporary/port-one") != "$(cat "$temporary/port-two")" ]] || { printf 'concurrent runs allocated one port\n' >&2; exit 1; }

# QEMU UNIX socket paths stay below the host limit, even with a long cache path.
long_runtime="$temporary/$(printf '%090d' 0)"
mkdir "$long_runtime"
socket_dir=$(XDG_RUNTIME_DIR="$long_runtime" bash -c "source '$script_dir/common.sh'; make_socket_dir")
[[ ${#socket_dir} -lt 98 ]] || { printf 'QEMU socket directory is too long\n' >&2; exit 1; }
bash -c "source '$script_dir/common.sh'; remove_socket_dir '$socket_dir'"
[[ ! -e "$socket_dir" ]] || { printf 'QEMU socket directory was not removed\n' >&2; exit 1; }

# An exited child is ready to reap even while it remains in the process table.
(exit 0) & exited_pid=$!
sleep 0.1
WINVM_CACHE_DIR="$temporary/pid-cache" bash -c "source '$script_dir/common.sh'; wait_for_pid '$exited_pid' 1"
wait "$exited_pid"

# A process that ignores SIGTERM is killed and reaped within the configured bound.
stubborn_ready="$temporary/stubborn.ready"
python3 -c 'import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1], "w").close(); time.sleep(300)' "$stubborn_ready" &
stubborn_pid=$!
for _ in {1..100}; do [[ -f "$stubborn_ready" ]] && break; sleep 0.01; done
[[ -f "$stubborn_ready" ]] || { printf 'stubborn process did not become ready\n' >&2; exit 1; }
export WINVM_CACHE_DIR="$temporary/pid-cache"
# shellcheck source=common.sh
source "$script_dir/common.sh"
stop_and_reap_pid "$stubborn_pid" 0 1 2
if kill -0 "$stubborn_pid" 2>/dev/null; then
    printf 'bounded process cleanup left its child running\n' >&2
    exit 1
fi

# An overlay reports its exact base as its backing file.
qemu-img create -q -f qcow2 "$temporary/base.qcow2" 1M
qemu-img create -q -f qcow2 -F qcow2 -b "$temporary/base.qcow2" "$temporary/overlay.qcow2"
overlay_backing=$(qemu-img info --output=json "$temporary/overlay.qcow2" | jq -r '."backing-filename"')
[[ $(realpath -e "$overlay_backing") == "$(realpath -e "$temporary/base.qcow2")" ]] || { printf 'overlay backing file changed\n' >&2; exit 1; }

# Cleanup is limited to the copied repository artifact root.
clean_repo="$temporary/clean-repo"
mkdir -p "$clean_repo/dev"
cp -R "$script_dir" "$clean_repo/dev/winvm"
mkdir -p "$clean_repo/.artifacts/winvm/run-one" "$clean_repo/outside"
printf 'keep\n' >"$clean_repo/outside/sentinel"
bash "$clean_repo/dev/winvm/run.sh" --clean >/dev/null
[[ -f "$clean_repo/outside/sentinel" ]] || { printf 'cleanup escaped its artifact root\n' >&2; exit 1; }
[[ -z $(find "$clean_repo/.artifacts/winvm" -mindepth 1 -print -quit) ]] || { printf 'cleanup left run artifacts\n' >&2; exit 1; }

# Fake sockets test QGA success, QMP negotiation, guest exit propagation, and timeout.
cat >"$temporary/fake-agent.py" <<'PY'
import json
import os
import socket
import sys
import time

path, mode = sys.argv[1:]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen()
while True:
    connection, _ = server.accept()
    with connection:
        if mode == "qmp":
            connection.sendall(b'{"QMP":{"version":{},"capabilities":[]}}\n')
        line = connection.makefile("rb").readline()
        if not line:
            continue
        request = json.loads(line)
        command = request["execute"]
        if mode == "qmp":
            connection.sendall(b'{"return":{}}\n')
            if command == "qmp_capabilities":
                line = connection.makefile("rb").readline()
                if line:
                    connection.sendall(b'{"return":{}}\n')
                break
        elif command == "guest-ping":
            connection.sendall(b'{"return":{}}\n')
            break
        elif command == "guest-exec":
            connection.sendall(b'{"return":{"pid":7}}\n')
        elif command == "guest-exec-status":
            if mode == "timeout":
                connection.sendall(b'{"return":{"exited":false}}\n')
            else:
                connection.sendall(b'{"return":{"exited":true,"exitcode":7}}\n')
                break
PY

socket_path="$temporary/qga.sock"
python3 "$temporary/fake-agent.py" "$socket_path" ping & server_pid=$!
for _ in {1..100}; do [[ -S "$socket_path" ]] && break; sleep 0.01; done
"$script_dir/tools/qga.py" --socket "$socket_path" ping
wait "$server_pid"

socket_path="$temporary/qmp.sock"
python3 "$temporary/fake-agent.py" "$socket_path" qmp & server_pid=$!
for _ in {1..100}; do [[ -S "$socket_path" ]] && break; sleep 0.01; done
"$script_dir/tools/qga.py" --socket "$socket_path" qmp send-key \
    --arguments '{"keys":[{"type":"qcode","data":"spc"}]}' >/dev/null
wait "$server_pid"

socket_path="$temporary/exit.sock"
python3 "$temporary/fake-agent.py" "$socket_path" exit & server_pid=$!
for _ in {1..100}; do [[ -S "$socket_path" ]] && break; sleep 0.01; done
set +e
"$script_dir/tools/qga.py" --socket "$socket_path" --timeout 2 exec cmd.exe /c exit 7
status=$?
set -e
wait "$server_pid"
[[ "$status" == 7 ]] || { printf 'guest exit status was %s, not 7\n' "$status" >&2; exit 1; }

socket_path="$temporary/timeout.sock"
python3 "$temporary/fake-agent.py" "$socket_path" timeout & server_pid=$!
for _ in {1..100}; do [[ -S "$socket_path" ]] && break; sleep 0.01; done
set +e
"$script_dir/tools/qga.py" --socket "$socket_path" --timeout 0.3 exec cmd.exe /c timeout >/dev/null 2>&1
status=$?
set -e
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
[[ "$status" != 0 ]] || { printf 'guest timeout returned success\n' >&2; exit 1; }

bash -n "$script_dir"/*.sh "$0"
PYTHONPYCACHEPREFIX="$temporary/pycache" python3 -m py_compile "$script_dir/tools/qga.py"
printf 'Windows VM host-script tests passed.\n'
