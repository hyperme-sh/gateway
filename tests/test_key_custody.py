import base64
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypermesh_ticket import TicketClaims, TicketError, issue_ticket, verify_ticket
from hypermesh_gateway_service.wg_identity import local_identity, public_key
from hypermesh_gateway_service.ticket_verifier import validate_verifier
from hypermesh_gateway_service.control_plane import HttpControlPlane


def test_fresh_gateway_keeps_one_private_identity_across_restart():
    first=local_identity([],registration_supported=True)
    assert local_identity([],registration_supported=True)==first
    path=os.environ['HYPERMESH_WG_PRIVATE_KEY_FILE']
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert public_key(first[0])==first[1]


def test_legacy_peer_adoption_preserves_public_identity_and_refuses_replacement():
    private=base64.b64encode(bytes(range(32))).decode(); public=public_key(private)
    rows=[{'status':'allocated','server_private_key':private,'server_public_key':public}]
    assert local_identity(rows,registration_supported=False)==(private,public)
    rows[0].pop('server_private_key')
    assert local_identity(rows,registration_supported=True)==(private,public)
    rows[0]['server_public_key']=public_key(base64.b64encode(bytes(range(1,33))).decode())
    with pytest.raises(ValueError,match='differs'):local_identity(rows,registration_supported=True)


def test_new_plane_cannot_supply_private_key_or_replace_lost_existing_identity():
    private=base64.b64encode(bytes(range(32))).decode()
    row={'status':'allocated','server_public_key':public_key(private),'server_private_key':private}
    with pytest.raises(ValueError,match='private key material'):local_identity([row],registration_supported=True)
    del row['server_private_key']
    with pytest.raises(ValueError,match='must be retained'):local_identity([row],registration_supported=True)


def test_public_only_verifier_cannot_sign_and_legacy_expires(monkeypatch):
    private=Ed25519PrivateKey.generate(); public=private.public_key()
    monkeypatch.delenv('HYPERMESH_TICKET_HMAC_KEY',raising=False)
    monkeypatch.setenv('HYPERMESH_TICKET_ED25519_PUBLIC_KEY',base64.b64encode(public.public_bytes(Encoding.Raw,PublicFormat.Raw)).decode())
    validate_verifier()
    now=datetime.now(UTC); fact=TicketClaims(uuid.uuid4(),uuid.uuid4(),uuid.uuid4(),'10.77.0.2/32','active',now+timedelta(minutes=5),tenant_id=uuid.uuid4())
    token=issue_ticket(fact,private_key=private)
    assert verify_ticket(token,gateway_id=fact.gateway_id).lease_id==fact.lease_id
    with pytest.raises(TicketError):issue_ticket(fact)
    legacy=issue_ticket(fact,key=b'legacy-unit-key')
    with pytest.raises(TicketError,match='overlap'):
        verify_ticket(legacy,gateway_id=fact.gateway_id,key=b'legacy-unit-key',hmac_accept_until=now,now=now)


@pytest.mark.parametrize('name',['HYPERMESH_TICKET_ED25519_PRIVATE_KEY','HYPERMESH_TICKET_ED25519_PRIVATE_KEY_FILE','HYPERMESH_DEV'])
def test_gateway_refuses_signing_configuration(monkeypatch,name):
    monkeypatch.setenv(name,'forbidden')
    with pytest.raises(ValueError,match='must not hold'):validate_verifier()


async def test_http_registration_sends_only_public_key_and_reuses_local_private(monkeypatch):
    sent=[]
    def handler(request):
        assert request.headers['authorization']=='Bearer hm_gw_unit'
        if request.method=='GET':return httpx.Response(200,json=[],headers={'X-Hypermesh-Gateway-Key-Custody':'public-v1'})
        import json
        body=json.loads(request.content);sent.append(body)
        assert set(body)=={'public_key'}
        return httpx.Response(200,json=body)
    original=httpx.AsyncClient
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kw:original(transport=httpx.MockTransport(handler),**kw))
    plane=HttpControlPlane('https://plane.invalid','hm_gw_unit'); tenant=uuid.uuid4()
    assert await plane.list_tunnels(tenant)==[]
    assert await plane.list_tunnels(tenant)==[]
    assert sent[0]==sent[1]


def test_existing_local_key_still_refuses_remote_private_material():
    private, public = local_identity([], registration_supported=True)
    with pytest.raises(ValueError, match="private key material"):
        local_identity([{"status": "allocated", "server_public_key": public,
                         "server_private_key": private}], registration_supported=True)


async def test_retained_identity_required_before_starting_gateway(app, monkeypatch):
    from asgi_lifespan import LifespanManager

    private = base64.b64encode(bytes(range(32))).decode()
    monkeypatch.setenv("HYPERMESH_WG_EXPECTED_PUBLIC_KEY", public_key(private))
    path = Path(os.environ["HYPERMESH_WG_PRIVATE_KEY_FILE"])
    with pytest.raises(ValueError, match="Provision the retained WireGuard identity"):
        async with LifespanManager(app):
            pytest.fail("Gateway started without the retained identity")
    assert not path.exists()
    assert not path.with_suffix(".lock").exists()


def test_retained_identity_preserves_the_same_key_across_the_pair(monkeypatch, tmp_path):
    private = base64.b64encode(bytes(range(32))).decode()
    public = public_key(private)
    monkeypatch.setenv("HYPERMESH_WG_EXPECTED_PUBLIC_KEY", public)
    for host in ("active", "passive"):
        path = tmp_path / host
        path.write_text(private + "\n")
        path.chmod(0o600)
        monkeypatch.setenv("HYPERMESH_WG_PRIVATE_KEY_FILE", str(path))
        assert local_identity([], registration_supported=True) == (private, public)
        assert local_identity([{"status": "allocated", "server_public_key": public}],
                              registration_supported=True) == (private, public)
        assert path.read_text() == private + "\n"
        assert not path.with_suffix(".lock").exists()


def test_retained_identity_refuses_wrong_local_or_plane_identity(monkeypatch):
    private = base64.b64encode(bytes(range(32))).decode()
    public = public_key(private)
    other_public = public_key(base64.b64encode(bytes(range(1, 33))).decode())
    path = Path(os.environ["HYPERMESH_WG_PRIVATE_KEY_FILE"])
    path.write_text(private)
    path.chmod(0o600)
    monkeypatch.setenv("HYPERMESH_WG_EXPECTED_PUBLIC_KEY", other_public)
    with pytest.raises(ValueError, match="differs from its configured public key"):
        local_identity([], registration_supported=True)
    monkeypatch.setenv("HYPERMESH_WG_EXPECTED_PUBLIC_KEY", public)
    with pytest.raises(ValueError, match="public-only Plane registration"):
        local_identity([], registration_supported=False)
    with pytest.raises(ValueError, match="differs from assigned peers"):
        local_identity([{"status": "allocated", "server_public_key": other_public}],
                       registration_supported=True)
    assert path.read_text() == private
