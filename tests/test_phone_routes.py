from types import SimpleNamespace
import uuid

from fastapi import HTTPException, Response
import pytest

from hypermesh_gateway_service import phone_routes as routes


@pytest.mark.parametrize("mode", ["disabled", "wrong_token", "wrong_tenant", "wrong_plane"])
async def test_no_peer_operation_without_dedicated_plane_auth(mode):
    tid = uuid.uuid4()
    body = routes.ProvisionBody(tenant_id=tid, device_id=uuid.uuid4(), request_id=uuid.uuid4(),
                                grant="hm_pm_" + "a" * 43)
    state = SimpleNamespace(phone_peers={"config": {"control_plane_id": "plane", "plane_token": "secret"}})
    request = SimpleNamespace(app=SimpleNamespace(state=state), headers={
        "X-Control-Plane-ID": "plane", "X-Phone-Plane-Token": "secret", "X-Tenant-ID": str(tid)})
    expected = 401
    if mode == "disabled": state.phone_peers = None; expected = 503
    if mode == "wrong_token": request.headers["X-Phone-Plane-Token"] = "wrong"
    if mode == "wrong_tenant": request.headers["X-Tenant-ID"] = str(uuid.uuid4()); expected = 403
    if mode == "wrong_plane": request.headers["X-Control-Plane-ID"] = "other"
    with pytest.raises(HTTPException) as error:
        await routes.provision(request, body, Response())
    assert error.value.status_code == expected


async def test_disabled_startup_does_not_load_or_apply_network(monkeypatch):
    monkeypatch.delenv("HYPERMESH_PHONE_CONFIG_FILE", raising=False)
    state = SimpleNamespace()
    async with routes.open_phone_peers(state):
        assert state.phone_peers is None
