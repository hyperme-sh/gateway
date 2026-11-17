"""Dedicated phone interface with kernel-expiring Conductor-only forwarding."""
from __future__ import annotations

import asyncio
import ipaddress
import math
from pathlib import Path
import subprocess
import time

from hypermesh_gateway_service.phone_mesh import PhoneUnavailable

INTERFACE = "wg-phone"
TABLE = "hm_phone"


def run(args, *, script=None):
    return subprocess.run(args, input=script, text=True, capture_output=True,
                          timeout=5, check=True).stdout


class KernelPhoneDriver:
    def __init__(self, conductor_ip: str, conductor_port: int, *, command=run):
        address = ipaddress.IPv4Address(conductor_ip)
        if not address.is_private or address.is_loopback or address.is_unspecified:
            raise ValueError("Private Conductor address required")
        if type(conductor_port) is not int or not 1 <= conductor_port <= 65535:
            raise ValueError("Conductor TCP port required")
        self.destination, self.port, self.command = str(address), conductor_port, command
        self.ready = False
        self.lock_file = None
        self.permissions = {}

    def rules(self):
        # Add is idempotent for tables. Create/delete in this atomic batch
        # handles first startup and restart using Debian's supported syntax.
        return f"""add table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
 set clients {{ type ipv4_addr; flags timeout; size 256; }}
 chain input {{ type filter hook input priority -20; policy accept;
  iifname "{INTERFACE}" drop
 }}
 chain forward {{ type filter hook forward priority -20; policy accept;
  iifname "{INTERFACE}" ip saddr @clients ip daddr {self.destination} tcp dport {self.port} accept
  iifname "{INTERFACE}" drop
  oifname "{INTERFACE}" ip daddr @clients ip saddr {self.destination} tcp sport {self.port} ct state established accept
  oifname "{INTERFACE}" drop
 }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
  iifname "{INTERFACE}" ip daddr {self.destination} tcp dport {self.port} masquerade
 }}
}}
"""

    async def initialize(self, private_key_file: str, gateway_cidr: str, listen_port: int,
                         lock_path: str = "/run/hypermesh-phone.lock"):
        await asyncio.to_thread(self._initialize, private_key_file, gateway_cidr, listen_port, lock_path)

    def _initialize(self, private_key_file, gateway_cidr, listen_port, lock_path):
        import fcntl
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
            raise PhoneUnavailable("Phone forwarding must be provisioned by the operator")
        key = Path(private_key_file)
        if not key.is_absolute() or not key.is_file() or key.stat().st_mode & 0o077:
            raise PhoneUnavailable("Dedicated private phone gateway key file required")
        address = ipaddress.IPv4Interface(gateway_cidr)
        if not address.ip.is_private or not 24 <= address.network.prefixlen <= 30:
            raise ValueError("Dedicated phone gateway subnet required")
        if type(listen_port) is not int or not 1 <= listen_port <= 65535:
            raise ValueError("Dedicated phone UDP port required")
        self.lock_file = open(lock_path, "a")
        try:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Reset only this dedicated interface. Never touch the host iface.
            interfaces = self.command(["ip", "-json", "link", "show"])
            import json
            if any(item["ifname"] == INTERFACE for item in json.loads(interfaces)):
                self.command(["ip", "link", "set", INTERFACE, "down"])
                self.command(["ip", "link", "delete", INTERFACE])
            self.command(["nft", "-f", "-"], script=self.rules())
            self.command(["ip", "link", "add", INTERFACE, "type", "wireguard"])
            self.command(["wg", "set", INTERFACE, "private-key", str(key), "listen-port", str(listen_port)])
            self.command(["ip", "address", "add", str(address), "dev", INTERFACE])
            self.command(["ip", "link", "set", INTERFACE, "up"])
            self.ready = True
        except BaseException:
            self.lock_file.close()
            self.lock_file = None
            raise

    async def apply(self, public_key: str, address: str, expires_at: int):
        await asyncio.to_thread(self._apply, public_key, address, expires_at)

    def _apply(self, public_key, address, expires_at):
        if not self.ready:
            raise PhoneUnavailable("Phone interface is unavailable")
        address = str(ipaddress.IPv4Address(address))
        self.command(["wg", "set", INTERFACE, "peer", public_key, "allowed-ips", address + "/32"])
        if expires_at - time.time() <= 5:
            raise PhoneUnavailable("Phone authorization has insufficient time remaining")
        self.permissions[address] = (expires_at, time.monotonic() + min(60, expires_at - time.time()))
        self._sync_permissions()

    def _sync_permissions(self):
        # Rebuild this small dedicated set atomically. Existing permissions
        # keep their original wall and monotonic deadlines across refreshes.
        wall, mono = time.time(), time.monotonic()
        active = {}
        elements = []
        for address, (expires, deadline) in self.permissions.items():
            seconds = math.floor(min(expires - wall, deadline - mono, 60) - 5)
            if seconds > 0:
                active[address] = (expires, deadline)
                elements.append(f"{address} timeout {seconds}s")
        self.permissions = active
        script = f"flush set inet {TABLE} clients\n"
        if elements:
            script += f"add element inet {TABLE} clients {{ " + ", ".join(elements) + " }\n"
        self.command(["nft", "-f", "-"], script=script)

    async def remove(self, public_key: str, address: str):
        await asyncio.to_thread(self._remove, public_key, address)

    def _remove(self, public_key, address):
        address = str(ipaddress.IPv4Address(address))
        self.permissions.pop(address, None)
        self._sync_permissions()
        self.command(["wg", "set", INTERFACE, "peer", public_key, "remove"])

    async def close(self):
        if self.ready:
            self.ready = False
            await asyncio.to_thread(self.command, ["ip", "link", "set", INTERFACE, "down"])
        if self.lock_file is not None:
            self.lock_file.close()
            self.lock_file = None
