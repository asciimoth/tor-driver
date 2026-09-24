#!/usr/bin/env python3
"""Small QEMU Guest Agent and QMP Unix-socket client."""

import argparse
import base64
import json
import socket
import sys
import time


class JSONSocket:
    def __init__(self, path: str, timeout: float):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        self.socket.connect(path)
        self.buffer = b""

    def close(self):
        self.socket.close()

    def send(self, value):
        self.socket.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")

    def receive(self):
        while b"\n" not in self.buffer:
            block = self.socket.recv(65536)
            if not block:
                raise RuntimeError("socket closed before a JSON response")
            self.buffer += block
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def response(self):
        while True:
            value = self.receive()
            if "event" in value or "QMP" in value:
                continue
            if "error" in value:
                raise RuntimeError(json.dumps(value["error"], sort_keys=True))
            if "return" in value:
                return value["return"]


def qga(path, timeout, command, arguments=None):
    client = JSONSocket(path, timeout)
    try:
        request = {"execute": command}
        if arguments:
            request["arguments"] = arguments
        client.send(request)
        return client.response()
    finally:
        client.close()


def guest_exec(path, timeout, executable, arguments):
    result = qga(
        path,
        timeout,
        "guest-exec",
        {
            "path": executable,
            "arg": arguments,
            "capture-output": True,
        },
    )
    pid = result["pid"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = qga(path, min(10, timeout), "guest-exec-status", {"pid": pid})
        if status.get("exited"):
            stdout = base64.b64decode(status.get("out-data", ""))
            stderr = base64.b64decode(status.get("err-data", ""))
            sys.stdout.buffer.write(stdout)
            sys.stderr.buffer.write(stderr)
            return int(status.get("exitcode", 0))
        time.sleep(0.25)
    raise TimeoutError(f"guest command did not finish in {timeout:g} seconds")


def qmp(path, timeout, command, arguments=None):
    client = JSONSocket(path, timeout)
    try:
        greeting = client.receive()
        if "QMP" not in greeting:
            raise RuntimeError("QMP greeting is absent")
        client.send({"execute": "qmp_capabilities"})
        client.response()
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        client.send(request)
        return client.response()
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--timeout", type=float, default=10)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("ping")
    shutdown = subparsers.add_parser("shutdown")
    shutdown.add_argument(
        "--mode", choices=("powerdown", "halt", "reboot"), default="powerdown"
    )
    execute = subparsers.add_parser("exec")
    execute.add_argument("executable")
    execute.add_argument("arguments", nargs=argparse.REMAINDER)
    monitor = subparsers.add_parser("qmp")
    monitor.add_argument("command")
    monitor.add_argument("--arguments", type=json.loads)
    args = parser.parse_args()

    if args.operation == "ping":
        qga(args.socket, args.timeout, "guest-ping")
        return 0
    if args.operation == "shutdown":
        qga(args.socket, args.timeout, "guest-shutdown", {"mode": args.mode})
        return 0
    if args.operation == "exec":
        return guest_exec(args.socket, args.timeout, args.executable, args.arguments)
    result = qmp(args.socket, args.timeout, args.command, args.arguments)
    if result not in (None, {}):
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"qga.py: {error}", file=sys.stderr)
        raise SystemExit(1)
