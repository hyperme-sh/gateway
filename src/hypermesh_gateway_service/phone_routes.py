"""Internal Plane bootstrap door; no renter or host token substitution."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hmac
import ipaddress
import json
import os
import subprocess
from pathlib import Path
import uuid

from fastapi import APIRouter, HTTPException, Request, Response
import httpx
from pydantic import BaseModel, ConfigDict, Field

from hypermesh_gateway_service.phone_mesh import Authority, PhoneIdentity, PhonePeers, PhoneUnavailable

router = APIRouter(prefix="/hypermesh-gateway/phone-peers", tags=["phone-peers"])


class IdentityBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: uuid.UUID
    device_id: uuid.UUID
    request_id: uuid.UUID


class ProvisionBody(IdentityBody):
    grant: str = Field(pattern=r"^hm_pm_[A-Za-z0-9_-]{43}$", repr=False)


def authenticated(request, body):
    service = getattr(request.app.state, "phone_peers", None)
    if service is None:
        raise HTTPException(503, "Phone mesh provisioning unavailable")
    config = service["config"]
    supplied = request.headers.get("X-Phone-Plane-Token", "")
    if (request.headers.get("X-Control-Plane-ID") != config["control_plane_id"]
            or not hmac.compare_digest(supplied.encode(), config["plane_token"].encode())):
        raise HTTPException(401, "Authenticated phone plane required")
    if request.headers.get("X-Tenant-ID") != str(body.tenant_id):
        raise HTTPException(403, "Phone tenant cross-check mismatch")
    try:
        identity = PhoneIdentity(str(body.tenant_id), config["control_plane_id"],
                                 str(body.device_id), str(body.request_id))
    except ValueError:
        raise HTTPException(400, "Invalid phone identity") from None
    return service, identity


@router.post("")
async def provision(request: Request, body: ProvisionBody, response: Response):
    response.headers["Cache-Control"] = "no-store"
    service, identity = authenticated(request, body)
    if service["inflight"] >= 8:
        raise HTTPException(429, "Phone provisioning budget exceeded")
    service["inflight"] += 1
    try:
        peer = await service["peers"].provision(identity, body.grant)
    except (PhoneUnavailable, OSError, subprocess.SubprocessError):
        raise HTTPException(503, "Phone peer unavailable; request fresh authorization") from None
    finally:
        service["inflight"] -= 1
    config = service["config"]
    return {"tenant_id": identity.tenant_id, "device_id": identity.device_id,
            "request_id": identity.request_id, "gateway_id": config["gateway_id"],
            "wg_public_key": peer.permission.public_key, "address": peer.address + "/32",
            "server_public_key": service["public_key"], "endpoint": config["public_endpoint"],
            "allowed_ips": [service["conductor_ip"] + "/32"],
            "conductor_origin": config["conductor_origin"], "expires_at": peer.permission.expires_at}


@router.post("/remove")
async def remove(request: Request, body: IdentityBody, response: Response):
    response.headers["Cache-Control"] = "no-store"
    service, identity = authenticated(request, body)
    peers = service["peers"]
    async with peers.lock:
        peer = peers.peers.get(identity)
        if peer is not None:
            try:
                await peers.driver.remove(peer.permission.public_key, peer.address)
            except (OSError, subprocess.SubprocessError):
                raise HTTPException(503, "Phone peer removal unavailable") from None
            del peers.peers[identity]
    return {"removed": True}


@asynccontextmanager
async def open_phone_peers(state):
    state.phone_peers = None
    configured = os.environ.get("HYPERMESH_PHONE_CONFIG_FILE")
    if not configured:
        yield
        return
    from hypermesh_gateway_service.phone_kernel import KernelPhoneDriver
    from hypermesh_gateway_service.wg_identity import public_key
    source = Path(configured)
    if not source.is_absolute() or not source.is_file() or source.stat().st_mode & 0o077:
        raise ValueError("Private phone configuration file required")
    config = json.loads(source.read_text())
    if not isinstance(config, dict):
        raise ValueError("Phone configuration object required")
    for secret in ("plane_token", "authority_token"):
        if not isinstance(config.get(secret), str) or len(config[secret]) < 32:
            raise ValueError("Dedicated phone service credentials required")
    if not isinstance(config.get("control_plane_id"), str) or not config["control_plane_id"]:
        raise ValueError("Phone control-plane ID required")
    origin = httpx.URL(config["conductor_origin"])
    if (origin.scheme != "https" or origin.username or origin.password
            or origin.path not in ("", "/") or origin.query or origin.fragment):
        raise ValueError("HTTPS Conductor origin required")
    conductor_ip = str(ipaddress.IPv4Address(origin.host))
    endpoint = httpx.URL("udp://" + config["public_endpoint"])
    if (not endpoint.host or endpoint.port is None or endpoint.username or endpoint.password
            or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment):
        raise ValueError("Phone public WireGuard endpoint required")
    gateway = ipaddress.IPv4Interface(config["gateway_address"])
    if ipaddress.IPv4Address(conductor_ip) in gateway.network:
        raise ValueError("Conductor cannot occupy the phone-only subnet")
    authority = Authority(config["authority_origin"], config["gateway_id"], config["authority_token"])
    driver = KernelPhoneDriver(conductor_ip, origin.port or 443)
    peers = PhonePeers(authority, driver, str(gateway.network), str(gateway.ip))
    await driver.initialize(config["private_key_file"], str(gateway), config["listen_port"])
    try:
        key = public_key(Path(config["private_key_file"]).read_text().strip())
        state.phone_peers = {"config": config, "peers": peers, "public_key": key,
                             "conductor_ip": conductor_ip, "inflight": 0}
        async def sweep():
            while True:
                await asyncio.sleep(1)
                try:
                    await peers.expire()
                except Exception:
                    # Kernel timeouts still close traffic. Retain allocations
                    # and retry cleanup instead of recycling uncertain peers.
                    continue
        task = asyncio.create_task(sweep())
        try:
            yield
        finally:
            state.phone_peers = None
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    finally:
        await driver.close()
