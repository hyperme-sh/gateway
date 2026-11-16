import base64
import uuid

import pytest

from hypermesh_gateway_service import phone_mesh as mesh


def identity():
    return mesh.PhoneIdentity(str(uuid.uuid4()), "plane", str(uuid.uuid4()), str(uuid.uuid4()))


class Authority:
    def __init__(self):
        self.key = base64.b64encode(bytes(range(32))).decode()
        self.allowed = True

    async def verify(self, caller, grant):
        if not self.allowed:
            raise mesh.PhoneUnavailable("denied")
        return mesh.Permission(caller, self.key, 1060)


class Driver:
    def __init__(self):
        self.applied, self.removed = [], []
        self.fail_apply = self.fail_remove = False

    async def apply(self, key, address, expires):
        self.applied.append((key, address, expires))
        if self.fail_apply: raise OSError("uncertain apply")

    async def remove(self, key, address):
        self.removed.append((key, address))
        if self.fail_remove: raise OSError("uncertain removal")


@pytest.fixture
def peers(monkeypatch):
    monkeypatch.setattr(mesh.time, "time", lambda: 1000)
    authority, driver = Authority(), Driver()
    return mesh.PhonePeers(authority, driver, "10.90.0.0/29", "10.90.0.1")


async def test_refusal_never_touches_driver(peers):
    peers.authority.allowed = False
    with pytest.raises(mesh.PhoneUnavailable):
        await peers.provision(identity(), "denied")
    assert not peers.driver.applied and not peers.peers


async def test_refresh_keeps_address_and_binds_kernel_deadline(peers):
    caller = identity()
    first = await peers.provision(caller, "grant")
    second = await peers.provision(caller, "fresh-grant")
    assert first.address == second.address == "10.90.0.2"
    assert peers.driver.applied[-1] == (peers.authority.key, "10.90.0.2", 1060)


async def test_key_cannot_cross_enrollments_or_change(peers):
    caller = identity()
    await peers.provision(caller, "grant")
    with pytest.raises(mesh.PhoneUnavailable):
        await peers.provision(identity(), "other")
    peers.authority.key = base64.b64encode(b"x" * 32).decode()
    with pytest.raises(mesh.PhoneUnavailable):
        await peers.provision(caller, "changed-key")
    assert len(peers.driver.applied) == 1


async def test_expired_peer_removed_before_address_reuse(peers, monkeypatch):
    await peers.provision(identity(), "grant")
    monkeypatch.setattr(mesh.time, "time", lambda: 1060)
    await peers.expire()
    assert not peers.peers and peers.driver.removed[0][1] == "10.90.0.2"


async def test_uncertain_apply_reserves_address_until_confirmed_removal(peers, monkeypatch):
    peers.driver.fail_apply = True
    with pytest.raises(OSError):
        await peers.provision(identity(), "grant")
    assert len(peers.peers) == 1
    monkeypatch.setattr(mesh.time, "time", lambda: 1060)
    peers.driver.fail_remove = True
    with pytest.raises(OSError): await peers.expire()
    assert len(peers.peers) == 1
    peers.driver.fail_remove = False
    await peers.expire()
    assert not peers.peers


async def test_removal_fences_authority_request_already_in_flight(peers):
    import asyncio
    caller = identity()
    entered, resume = asyncio.Event(), asyncio.Event()
    original = peers.authority.verify
    async def delayed(identity, grant):
        permission = await original(identity, grant)
        entered.set()
        await resume.wait()
        return permission
    peers.authority.verify = delayed
    task = asyncio.create_task(peers.provision(caller, "grant"))
    await entered.wait()
    await peers.remove(caller)
    resume.set()
    with pytest.raises(mesh.PhoneUnavailable): await task
    assert not peers.driver.applied and not peers.peers and not peers.pending


@pytest.mark.parametrize("origin", ["http://authority", "https://a/path", "https://user:pass@a", "https://a?x=1"])
def test_authority_origin_is_fixed_https(origin):
    with pytest.raises(ValueError): mesh.Authority(origin, "gateway", "secret")


@pytest.mark.parametrize("change", [None, "tenant_id", "gateway_id", "expires_at", "wg_public_key", "active"])
async def test_http_authority_binds_every_permission_field(monkeypatch, change):
    import httpx
    caller = identity()
    monkeypatch.setattr(mesh.time, "time", lambda: 1000)
    payload = {"active": True, "tenant_id": caller.tenant_id, "control_plane_id": "plane",
               "device_id": caller.device_id, "request_id": caller.request_id,
               "gateway_id": "gateway", "wg_public_key": base64.b64encode(b"x" * 32).decode(),
               "expires_at": 1060}
    if change: payload[change] = {"expires_at": 1000, "active": False}.get(change, "other")
    def handler(request):
        assert str(request.url) == "https://authority/api/v1/aiuditor/machine/client-mesh-introspect"
        assert request.headers["X-Phone-Gateway-Token"] == "secret"
        assert request.headers["X-Tenant-ID"] == caller.tenant_id
        return httpx.Response(200, json=payload)
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    authority = mesh.Authority("https://authority", "gateway", "secret")
    if change:
        with pytest.raises(mesh.PhoneUnavailable): await authority.verify(caller, "grant")
    else:
        result = await authority.verify(caller, "grant")
        assert result.identity == caller and result.expires_at == 1060
