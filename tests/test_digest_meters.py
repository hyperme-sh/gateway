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
    assert calls[0]==calls[2]
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


async def test_refused_lease_does_not_starve_other_tenants(tmp_path):
    q=DigestQueue(tmp_path/'counts.db');bad=uuid.uuid4();good=uuid.uuid4();lease=uuid.uuid4()
    for _ in range(101):
        identifier=q.begin(bad,lease,['token_digest_count']);q.finish(identifier,1)
    identifier=q.begin(good,lease,['token_digest_count']);q.finish(identifier,2)
    sent=[]
    async def post(tenant,resource,payload):
        if tenant==bad:raise PermissionError('reassigned')
        sent.append(payload)
    plane=SimpleNamespace(post_reading=post)
    await q.flush(plane);await q.flush(plane)
    assert len(sent)==1 and q.drained(good,lease) and not q.drained(bad,lease)
    q.close()


async def test_ir_rejection_does_not_leave_pending_count(http_client,tenant_headers,app,tenant_id,tmp_path,monkeypatch):
    from dataclasses import replace
    from fastapi import HTTPException
    from test_hypermesh_gateway import _signed_ticket,_ir
    from hypermesh_gateway_service import routes
    lease=uuid.uuid4()
    app.state.ticket_cache.put(tenant_id,replace(_signed_ticket(lease,purpose='ir'),digest_meters=('token_digest_count',)))
    queue=DigestQueue(tmp_path/'counts.db');app.state.digest_queue=queue
    monkeypatch.setattr(routes,'_load_policies',AsyncMock(return_value=[]))
    monkeypatch.setattr(routes,'_classifier',lambda request:SimpleNamespace(classify=lambda text:SimpleNamespace(decision='allow',prompt_class='benign',pack_version='unit')))
    def reject(*args):raise HTTPException(409,'run paused')
    monkeypatch.setattr(routes,'_gate_router_run',reject)
    response=await http_client.post('/v1/ir/chat/completions',headers=_ir(tenant_headers),json={'lease_id':str(lease),'messages':[{'role':'user','content':'hello'}]})
    assert response.status_code==409,response.text
    assert queue.db.execute('SELECT count(*) FROM requests').fetchone()[0]==0


async def test_finishing_counts_does_not_await_delivery(tmp_path):
    from hypermesh_gateway_service.routes import _finish_digest
    queue=DigestQueue(tmp_path/'counts.db');tenant,lease=uuid.uuid4(),uuid.uuid4()
    identifier=queue.begin(tenant,lease,['token_digest_count'])
    plane=SimpleNamespace(post_reading=AsyncMock(side_effect=AssertionError('network before session counters')))
    req=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(digest_queue=queue,control_plane=plane)))
    proxied=SimpleNamespace(count_complete=True,count_parser=SimpleNamespace(finish=lambda:3))
    await _finish_digest(req,identifier,proxied)
    assert queue.db.execute('SELECT quantity FROM batches').fetchone()[0]==3
    plane.post_reading.assert_not_awaited()
    queue.close()


def test_unresolved_markers_are_bounded_per_lease_and_tenant(tmp_path):
    q=DigestQueue(tmp_path/'counts.db');tenant,lease=uuid.uuid4(),uuid.uuid4()
    for _ in range(128):q.begin(tenant,lease,['token_digest_count'])
    with pytest.raises(ValueError,match='Lease'):q.begin(tenant,lease,['token_digest_count'])
    assert q.begin(uuid.uuid4(),lease,['token_digest_count'])
    q.close()


async def test_acknowledged_rows_are_deleted_only_after_all_meters(tmp_path):
    q=DigestQueue(tmp_path/'counts.db');tenant,lease=uuid.uuid4(),uuid.uuid4()
    identifier=q.begin(tenant,lease,['prompt_digest_count','token_digest_count']);q.finish(identifier,5)
    async def post(t,l,p):
        if p['meter']=='token_digest_count':raise RuntimeError('offline')
    await q.flush(SimpleNamespace(post_reading=post))
    assert q.db.execute('SELECT count(*) FROM requests').fetchone()[0]==1
    await q.flush(SimpleNamespace(post_reading=AsyncMock()))
    assert q.db.execute('SELECT count(*) FROM requests').fetchone()[0]==0
    assert q.db.execute('SELECT count(*) FROM batches').fetchone()[0]==0
    q.close()


@pytest.mark.parametrize('failure',['connect','reject','ambiguous'])
async def test_proxy_classifies_no_work_without_guessing(failure):
    import httpx
    from hypermesh_gateway_service.chat import proxy_chat
    from fastapi import HTTPException
    def handle(request):
        if failure=='connect':raise httpx.ConnectError('refused')
        if failure=='ambiguous':raise httpx.ReadTimeout('lost response')
        return httpx.Response(503,json={'error':'loading'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(HTTPException) as error:
            await proxy_chat(lease_id=uuid.uuid4(),payload={},client_address='192.0.2.1',runtime_client=client)
    assert error.value.count_not_started == (failure!='ambiguous')


@pytest.mark.parametrize('path,purpose',[('/v1/chat/completions','renter'),('/v1/ir/chat/completions','ir')])
async def test_refused_host_does_not_block_drain(http_client,tenant_headers,app,tenant_id,tmp_path,monkeypatch,path,purpose):
    from dataclasses import replace
    from test_hypermesh_gateway import _signed_ticket,_ir,_renter
    from hypermesh_gateway_service import routes
    from hypermesh_gateway_service.chat import unstarted_error
    lease=uuid.uuid4();queue=DigestQueue(tmp_path/'counts.db');app.state.digest_queue=queue
    app.state.ticket_cache.put(tenant_id,replace(_signed_ticket(lease,purpose=purpose),digest_meters=('token_digest_count',)))
    monkeypatch.setattr(routes,'_load_policies',AsyncMock(return_value=[]))
    monkeypatch.setattr(routes,'_classifier',lambda request:SimpleNamespace(classify=lambda text:SimpleNamespace(decision='allow',prompt_class='benign',pack_version='unit')))
    monkeypatch.setattr(routes,'proxy_chat',AsyncMock(side_effect=unstarted_error('host_status_503')))
    response=await http_client.post(path,headers=(_ir if purpose=='ir' else _renter)(tenant_headers),json={'lease_id':str(lease),'messages':[{'role':'user','content':'hello'}]})
    assert response.status_code==409,response.text
    assert queue.drained(tenant_id,lease)
