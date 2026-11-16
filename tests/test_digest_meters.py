"""Count-only producer contracts with isolated SQLite and HTTP doubles."""
import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from hypermesh_gateway_service.digest_meters import Counts, DigestQueue, configured, selected


def test_counts_chunked_sse_and_json():
    raw=b'data: {"choices":[],"usage":{"total_tokens":17}}\n\ndata: [DONE]\n'
    parser=Counts(True)
    for char in raw: parser.feed(bytes([char]))
    assert parser.finish()==17 and parser.buffer==b''
    parser=Counts(False);parser.feed(b'{"usage":{"total_tokens":0}}')
    assert parser.finish()==0


@pytest.mark.parametrize('value',[True,-1,1.2,'3',2**63])
def test_invalid_counts_never_become_charges(value):
    parser=Counts(False);parser.feed(json.dumps({'usage':{'total_tokens':value}}).encode())
    assert parser.finish() is None


def test_bounds_and_conflicting_counts():
    parser=Counts(True);parser.feed(b'x'*(1024*1024+1))
    assert parser.finish() is None and parser.buffer==b''
    parser=Counts(True)
    parser.feed(b'data: {"usage":{"total_tokens":1}}\ndata: {"usage":{"total_tokens":2}}\n')
    assert parser.finish() is None


async def test_restart_lost_ack_and_drain_fence(tmp_path):
    path=tmp_path/'counts.db';tenant,lease=uuid.uuid4(),uuid.uuid4()
    queue=DigestQueue(path);identifier=queue.begin(tenant,lease,['token_digest_count','prompt_digest_count'])
    assert not queue.drained(tenant,lease)
    assert queue.finish(identifier,123)
    calls=[]
    async def post(t,l,p):
        calls.append((t,l,p))
        if len(calls)==1:raise RuntimeError('lost acknowledgement')
    plane=SimpleNamespace(post_reading=post)
    await queue.flush(plane);queue.close()
    queue=DigestQueue(path);queue.fence(tenant,lease)
    with pytest.raises(ValueError,match='draining'):queue.begin(tenant,lease,['token_digest_count'])
    await queue.flush(plane)
    assert calls[0]==calls[1]
    assert {x[2]['quantity'] for x in calls}=={1,123}
    assert all(set(x[2])=={'meter','quantity','batch_id'} for x in calls)
    assert all(x[2]['batch_id']==identifier for x in calls)
    assert queue.drained(tenant,lease)
    await queue.flush(plane);assert len(calls)==3
    queue.close()


def test_unknown_count_survives_restart_and_blocks_close(tmp_path):
    path=tmp_path/'counts.db';tenant,lease=uuid.uuid4(),uuid.uuid4()
    q=DigestQueue(path);identifier=q.begin(tenant,lease,['token_digest_count'])
    assert not q.finish(identifier,None)
    q.close();q=DigestQueue(path)
    assert not q.drained(tenant,lease)
    assert q.drained(uuid.uuid4(),lease)
    assert q.db.execute('SELECT count(*) FROM batches').fetchone()[0]==0
    q.close()


def test_configuration_requires_durable_storage(monkeypatch,tmp_path):
    monkeypatch.delenv('HYPERMESH_DIGEST_METERS_ENABLED',raising=False)
    assert configured() is None
    monkeypatch.setenv('HYPERMESH_DIGEST_METERS_ENABLED','true')
    monkeypatch.delenv('HYPERMESH_DIGEST_QUEUE_PATH',raising=False)
    with pytest.raises(ValueError,match='Durable'):configured()
    monkeypatch.setenv('HYPERMESH_DIGEST_QUEUE_PATH',str(tmp_path/'counts.db'))
    configured().close()
    with pytest.raises(ValueError):selected(['bad'])


async def test_drain_auth_scope_and_pending(tmp_path):
    from hypermesh_gateway_service.routes import drain_digest
    from fastapi import HTTPException
    tenant,lease,gateway=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
    q=DigestQueue(tmp_path/'counts.db')
    cached=SimpleNamespace(digest_meters=('token_digest_count',),assigned_gateway_id=gateway)
    plane=SimpleNamespace(gateway_identity=AsyncMock(return_value=gateway),post_reading=AsyncMock())
    state=SimpleNamespace(gateway_service_secret='test-secret',digest_queue=q,
        ticket_cache=SimpleNamespace(get=lambda t,l:cached if (t,l)==(tenant,lease) else None),control_plane=plane)
    req=SimpleNamespace(app=SimpleNamespace(state=state),headers={'X-Tenant-ID':str(tenant)})
    with pytest.raises(HTTPException) as err:await drain_digest(req,lease)
    assert err.value.status_code==401
    req.headers['Authorization']='Bearer test-secret'
    identifier=q.begin(tenant,lease,['token_digest_count'])
    with pytest.raises(HTTPException) as err:await drain_digest(req,lease)
    assert err.value.status_code==409
    q.finish(identifier,3)
    assert (await drain_digest(req,lease))['drained'] is True
    state.ticket_cache=SimpleNamespace(get=lambda t,l:None)
    assert (await drain_digest(req,lease))['drained'] is True
    state.ticket_cache=SimpleNamespace(get=lambda t,l:cached)
    plane.gateway_identity.return_value=uuid.uuid4()
    with pytest.raises(HTTPException) as err:await drain_digest(req,lease)
    assert err.value.status_code==403
    q.close()

async def test_stream_count_hook_and_count_only_batches(tmp_path):
    import httpx
    from hypermesh_gateway_service.chat import ProxiedChat, iter_chat_bytes
    from hypermesh_gateway_service.routes import _finish_digest
    tenant,lease=uuid.uuid4(),uuid.uuid4()
    queue=DigestQueue(tmp_path/'counts.db')
    identifier=queue.begin(tenant,lease,['token_digest_count','prompt_digest_count'])
    secret='never write this response text to queue'
    payload={'choices':[{'message':{'content':secret}}],'usage':{'total_tokens':23}}
    proxied=ProxiedChat(httpx.Response(200,json=payload));proxied.count_parser=Counts(False)
    output=b''.join([part async for part in iter_chat_bytes(proxied)])
    assert secret.encode() in output
    plane=SimpleNamespace(post_reading=AsyncMock(side_effect=RuntimeError('offline')))
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(digest_queue=queue,control_plane=plane)))
    await _finish_digest(request,identifier,proxied)
    assert not queue.drained(tenant,lease)
    assert secret.encode() not in (tmp_path/'counts.db').read_bytes()
    plane.post_reading.side_effect=None
    await queue.flush(plane)
    assert queue.drained(tenant,lease)
    queue.close()


async def test_http_reading_retries_unchanged_and_rejects_wrong_scope(monkeypatch):
    import httpx
    from hypermesh_gateway_service.control_plane import HttpControlPlane
    tenant,lease=uuid.uuid4(),uuid.uuid4();calls=[];reply={'id':str(lease),'tenant_id':str(tenant)}
    def handle(request):
        calls.append(request)
        return httpx.Response(200,json=reply)
    original=httpx.AsyncClient
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kw:original(transport=httpx.MockTransport(handle),**kw))
    plane=HttpControlPlane(base_url='https://plane.example',service_secret='hm_gw_unit')
    payload={'meter':'token_digest_count','quantity':8,'batch_id':str(uuid.uuid4())}
    await plane.post_reading(tenant,lease,payload)
    await plane.post_reading(tenant,lease,payload)
    assert calls[0].content==calls[1].content
    assert calls[0].headers['Authorization']=='Bearer hm_gw_unit'
    reply['tenant_id']=str(uuid.uuid4())
    with pytest.raises(RuntimeError,match='mismatch'):await plane.post_reading(tenant,lease,payload)
