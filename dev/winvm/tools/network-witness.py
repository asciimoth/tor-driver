#!/usr/bin/env python3
"""Private host listeners for the Windows containment VM gate."""

import json
import selectors
import socket
import sys


def listener(family, kind, address):
    sock = socket.socket(family, kind)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind(address)
    if kind == socket.SOCK_STREAM:
        sock.listen()
    sock.setblocking(False)
    return sock


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: network-witness.py READY.json")
    tcp4 = listener(socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 0))
    tcp6 = listener(socket.AF_INET6, socket.SOCK_STREAM, ("::1", 0))
    udp4 = listener(socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 0))
    with open(sys.argv[1], "x", encoding="utf-8") as ready:
        json.dump(
            {
                "tcp4": tcp4.getsockname()[1],
                "tcp6": tcp6.getsockname()[1],
                "udp4": udp4.getsockname()[1],
            },
            ready,
        )
    selector = selectors.DefaultSelector()
    selector.register(tcp4, selectors.EVENT_READ, "tcp")
    selector.register(tcp6, selectors.EVENT_READ, "tcp")
    selector.register(udp4, selectors.EVENT_READ, "udp")
    while True:
        for key, _ in selector.select():
            if key.data == "tcp":
                connection, _ = key.fileobj.accept()
                connection.close()
            else:
                data, address = key.fileobj.recvfrom(512)
                key.fileobj.sendto(data, address)


if __name__ == "__main__":
    main()
