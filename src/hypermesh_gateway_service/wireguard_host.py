"""A local peer API for the host-managed WireGuard interface."""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time


MAX_MESSAGE = 1024
SOCKET_ENV = "HYPERMESH_WG_HOST_SOCKET"


def enabled() -> bool:
    return SOCKET_ENV in os.environ


def public_key(value: str) -> str:
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("Invalid WireGuard public key")
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Invalid WireGuard public key")
    return value


def read_message(connection: socket.socket) -> dict:
    deadline = time.monotonic() + connection.gettimeout()
    raw = bytearray()
    while b"\n" not in raw and len(raw) <= MAX_MESSAGE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("WireGuard host message deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(MAX_MESSAGE + 1 - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
    if not raw.endswith(b"\n") or len(raw) > MAX_MESSAGE:
        raise ValueError("Invalid WireGuard host message")
    message = json.loads(raw)
    if not isinstance(message, dict):
        raise ValueError("Invalid WireGuard host message")
    return message


def send_message(connection: socket.socket, message: dict) -> None:
    raw = json.dumps(message, separators=(",", ":")).encode() + b"\n"
    if len(raw) > MAX_MESSAGE:
        raise ValueError("Invalid WireGuard host message")
    connection.sendall(raw)


def request(operation: str, **fields) -> dict:
    try:
        path = Path(os.environ[SOCKET_ENV])
        if not path.is_absolute() or len(os.fsencode(path)) > 107:
            raise ValueError("Invalid WireGuard host socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(4)
            connection.connect(str(path))
            send_message(connection, {"operation": operation, **fields})
            reply = read_message(connection)
        if reply.get("ok") is not True:
            raise ValueError("WireGuard host request refused")
        return reply
    except (KeyError, OSError, TypeError, ValueError):
        raise RuntimeError("WireGuard host service unavailable or refused the request") from None


def identity(expected: str) -> str:
    expected = public_key(expected)
    reply = request("identity")
    if set(reply) != {"ok", "public_key"} or reply["public_key"] != expected:
        raise ValueError("WireGuard host public identity differs from production configuration")
    return expected


def peer_stats(peer: str) -> tuple[int, int, int]:
    reply = request("stats", peer=peer)
    values = tuple(reply.get(field) for field in ("handshake", "rx", "tx"))
    if any(type(value) is not int or value < 0 for value in values):
        raise RuntimeError("Invalid WireGuard host peer counters")
    return values


class Interface:
    def __init__(self, name, network, expected, *, run=subprocess.run):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            raise ValueError("Invalid WireGuard interface")
        self.name = name
        self.network = ipaddress.IPv4Network(network)
        if self.network.prefixlen > 30:
            raise ValueError("Expected a WireGuard peer network")
        self.expected = public_key(expected)
        self.run = run

    def wg(self, *arguments):
        return self.run(["/usr/bin/wg", *arguments], check=True, capture_output=True,
                        text=True, timeout=2).stdout.strip()

    def handle(self, message):
        operation = message.get("operation")
        expected_fields = {
            "identity": {"operation"},
            "apply": {"operation", "peer", "address"},
            "remove": {"operation", "peer"},
            "stats": {"operation", "peer"},
        }
        if not isinstance(operation, str) or set(message) != expected_fields.get(operation):
            raise ValueError("Unsupported WireGuard host operation")
        if self.wg("show", self.name, "public-key") != self.expected:
            raise ValueError("WireGuard host interface is unavailable or has a different identity")
        if operation == "identity":
            return {"ok": True, "public_key": self.expected}
        peer = public_key(message["peer"])
        if peer == self.expected:
            raise ValueError("WireGuard interface key cannot be a peer")
        if operation == "apply":
            if not isinstance(message["address"], str):
                raise ValueError("Expected an IPv4 peer address")
            address = ipaddress.IPv4Address(message["address"])
            if address not in self.network or address in {
                self.network.network_address, self.network.broadcast_address,
                self.network.network_address + 1,
            }:
                raise ValueError("Peer address is outside the assigned WireGuard host range")
            for row in self.wg("show", self.name, "allowed-ips").splitlines():
                owner, *routes = row.replace(",", " ").split()
                if owner != peer and any(address in ipaddress.ip_network(route)
                                         for route in routes if route != "(none)"):
                    raise ValueError("WireGuard route belongs to a different peer")
            self.wg("set", self.name, "peer", peer, "allowed-ips", f"{address}/32")
        elif operation == "remove":
            self.wg("set", self.name, "peer", peer, "remove")
        else:
            handshake = next((row.split()[1:] for row in self.wg(
                "show", self.name, "latest-handshakes").splitlines() if row.startswith(peer + "\t")), [0])
            traffic = next((row.split()[1:] for row in self.wg(
                "show", self.name, "transfer").splitlines() if row.startswith(peer + "\t")), [0, 0])
            epoch, = map(int, handshake)
            rx, tx = map(int, traffic)
            return {"ok": True, "handshake": epoch, "rx": rx, "tx": tx}
        return {"ok": True}


def serve(listener: socket.socket, interface: Interface) -> None:
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(2)
            try:
                reply = interface.handle(read_message(connection))
                send_message(connection, reply)
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                try:
                    send_message(connection, {"ok": False})
                except OSError:
                    pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--public-key", required=True)
    args = parser.parse_args()
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        parser.exit(1, "One systemd-owned WireGuard host socket is required\n")
    interface = Interface(args.interface, args.network, args.public_key)
    with socket.socket(fileno=3) as listener:
        if listener.family != socket.AF_UNIX or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
            parser.exit(1, "Expected a listening Unix socket\n")
        serve(listener, interface)


if __name__ == "__main__":
    main()
