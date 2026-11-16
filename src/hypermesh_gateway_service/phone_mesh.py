"""Phone-only peer allocation after a current AIuditor decision.

The driver must enforce expiry in the kernel and restrict traffic to the
configured Conductor destination. Host peer helpers are deliberately separate.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass
import ipaddress
import time
from typing import Protocol
import uuid

import httpx


class PhoneUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class PhoneIdentity:
    tenant_id: str
    control_plane_id: str
    device_id: str
    request_id: str

    def __post_init__(self):
        for value in (self.tenant_id, self.device_id, self.request_id):
            if str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
                raise ValueError("Canonical nonzero phone identifiers required")


@dataclass(frozen=True)
class Permission:
    identity: PhoneIdentity
    public_key: str
    expires_at: int


class Authority:
    """Fixed-origin verification; no redirects or caller-selected destination."""
    def __init__(self, origin: str, gateway_id: str, token: str):
        url = httpx.URL(origin)
        if (url.scheme != "https" or not url.host or url.username or url.password
                or url.query or url.fragment or url.path not in ("", "/")):
            raise ValueError("HTTPS authority origin required")
        if not gateway_id or not token:
            raise ValueError("Phone gateway credentials required")
        self.origin, self.gateway_id, self.token = origin.rstrip("/"), gateway_id, token

    async def verify(self, identity: PhoneIdentity, grant: str) -> Permission:
        headers = {"X-Tenant-ID": identity.tenant_id,
                   "X-Phone-Gateway-ID": self.gateway_id,
                   "X-Phone-Gateway-Token": self.token}
        body = {"control_plane_id": identity.control_plane_id,
                "device_id": identity.device_id, "request_id": identity.request_id, "grant": grant}
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
                async with client.stream("POST", self.origin + "/api/v1/aiuditor/machine/client-mesh-introspect",
                                         headers=headers, json=body) as response:
                    if response.status_code != 200:
                        raise PhoneUnavailable("Phone authority refused verification")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 8192:
                            raise PhoneUnavailable("Phone authority response exceeds limit")
            import json
            result = json.loads(raw)
            expected = {"tenant_id": identity.tenant_id, **{k: v for k, v in body.items() if k != "grant"},
                        "gateway_id": self.gateway_id}
            if (not isinstance(result, dict) or result.get("active") is not True
                    or any(result.get(k) != v for k, v in expected.items())):
                raise ValueError()
            key, expires = result["wg_public_key"], result["expires_at"]
            decoded = base64.b64decode(key, validate=True)
            if (len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode() != key
                    or type(expires) is not int or not time.time() < expires <= time.time() + 60):
                raise ValueError()
            return Permission(identity, key, expires)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise PhoneUnavailable("Phone authority unavailable or invalid") from None


class Driver(Protocol):
    async def apply(self, public_key: str, address: str, expires_at: int) -> None:
        """Apply phone peer and kernel-enforced expiry; raise if not enforced."""
        ...

    async def remove(self, public_key: str, address: str) -> None: ...


@dataclass(frozen=True)
class Peer:
    permission: Permission
    address: str
    grant_digest: str


@dataclass
class Pending:
    grant_digest: str
    cancelled: bool = False


class PhonePeers:
    def __init__(self, authority: Authority, driver: Driver, pool: str, gateway_address: str):
        network = ipaddress.IPv4Network(pool, strict=True)
        gateway = ipaddress.IPv4Address(gateway_address)
        if not network.is_private or not 24 <= network.prefixlen <= 30 or gateway not in network.hosts():
            raise ValueError("Dedicated bounded private phone subnet required")
        self.addresses = tuple(str(ip) for ip in network.hosts() if ip != gateway)
        self.authority, self.driver = authority, driver
        self.peers: dict[PhoneIdentity, Peer] = {}
        self.pending: dict[PhoneIdentity, list[Pending]] = {}
        self.lock = asyncio.Lock()

    async def remove(self, identity: PhoneIdentity, grant: str | None = None):
        digest = hashlib.sha256(grant.encode()).hexdigest() if grant is not None else None
        async with self.lock:
            # Fence even a first provisioning request still awaiting authority.
            for operation in self.pending.get(identity, []):
                if digest is None or operation.grant_digest == digest:
                    operation.cancelled = True
            peer = self.peers.get(identity)
            if peer is not None and (digest is None or peer.grant_digest == digest):
                await self.driver.remove(peer.permission.public_key, peer.address)
                del self.peers[identity]

    async def expire(self):
        async with self.lock:
            await self._expire()

    async def _expire(self):
        for identity, peer in list(self.peers.items()):
            if peer.permission.expires_at <= time.time():
                # Never recycle an address after an uncertain kernel removal.
                await self.driver.remove(peer.permission.public_key, peer.address)
                del self.peers[identity]

    async def provision(self, identity: PhoneIdentity, grant: str) -> Peer:
        operation = Pending(hashlib.sha256(grant.encode()).hexdigest())
        self.pending.setdefault(identity, []).append(operation)
        try:
            permission = await self.authority.verify(identity, grant)
            return await self._provision(identity, permission, operation)
        finally:
            operations = self.pending[identity]
            # Remove by identity: equal uncancelled flags are separate calls.
            operations[:] = [item for item in operations if item is not operation]
            if not operations:
                del self.pending[identity]

    async def _provision(self, identity, permission, operation):
        async with self.lock:
            await self._expire()
            if operation.cancelled or permission.identity != identity or permission.expires_at <= time.time():
                raise PhoneUnavailable("Phone authorization expired")
            existing = self.peers.get(identity)
            if existing and existing.permission.public_key != permission.public_key:
                raise PhoneUnavailable("Phone public key changed within enrollment")
            if any(p.permission.public_key == permission.public_key and i != identity
                   for i, p in self.peers.items()):
                raise PhoneUnavailable("Phone public key belongs to another enrollment")
            if existing:
                address = existing.address
            else:
                used = {p.address for p in self.peers.values()}
                address = next((a for a in self.addresses if a not in used), None)
                if address is None:
                    raise PhoneUnavailable("Phone address pool is full")
            # Reserve before applying: uncertain application must not free the
            # address for a different phone. Expiry cleanup retries removal.
            peer = Peer(permission, address, operation.grant_digest)
            self.peers[identity] = peer
            await self.driver.apply(permission.public_key, address, permission.expires_at)
            if permission.expires_at <= time.time():
                await self._expire()
                raise PhoneUnavailable("Phone authorization expired during apply")
            return peer
