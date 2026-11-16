"""Count, authority and guest protocol contracts with isolated transport doubles."""

import asyncio
import json
import time
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypermesh_gateway_service.digest_meters import DigestQueue
from hypermesh_gateway_service.trusted_meter import policy
from hypermesh_gateway_service.trusted_meter.client import Consumer, execution_payload
from hypermesh_gateway_service.trusted_meter.wire import (
    canonical,
    digest,
    DOMAIN,
    POLICY_DIGEST,
    Refusal,
)


def signed(key, record, domain=DOMAIN):
    return {"record": record, "signature": key.sign(domain + canonical(record)).hex()}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    owner, runtime, issuer = [Ed25519PrivateKey.generate() for _ in range(3)]
    tenant, lease, device, gateway, epoch, start = [str(uuid.uuid4()) for _ in range(6)]
    runtime_key = runtime.public_key().public_bytes_raw().hex()
    profile = dict(
        model_sha256="1" * 64,
        tokenizer_sha256="1" * 64,
        template_sha256="2" * 64,
        runtime_sha256="3" * 64,
        measurement="4" * 96,
    )
    binding = profile | dict(
        tenant_id=tenant,
        lease_id=lease,
        device_id=device,
        gateway_id=gateway,
        policy_sha256=POLICY_DIGEST,
    )
    cfg = policy.Policy(
        owner_key=owner.public_key().public_bytes_raw().hex(),
        issuer="qualified-test",
        issuer_key=issuer.public_key().public_bytes_raw().hex(),
        issuer_command={"executable": "/unit/issuer", "sha256": "5" * 64},
        verifier={"executable": "/unit/check", "sha256": "6" * 64},
        profiles={"model": profile},
        product="Genoa",
        minimum_tcb=1,
        minimum_launch_tcb=1,
        policy_expires_at=int(time.time()) + 1000,
        relay_bind="127.0.0.1",
        relay_port=18080,
        relay_url="https://gateway.example:18080/trusted-meter/relay",
    )
    monkeypatch.setattr(policy, "configured", lambda: cfg)
    q = DigestQueue(tmp_path / "counts.db")
    batch = q.begin(tenant, lease, ["token_digest_count", "prompt_digest_count"])
    state = SimpleNamespace(
        owner=owner,
        runtime=runtime,
        issuer=issuer,
        binding=binding,
        config=cfg,
        tenant=tenant,
        lease=lease,
        epoch=epoch,
        start=start,
        batch=batch,
        q=q,
        calls=[],
        guest_calls=[],
        terminal=None,
        mutate=lambda operation, result: result,
        fail=None,
    )

    async def plane(tenant_arg, lease_arg, operation, payload):
        assert str(tenant_arg) == tenant and str(lease_arg) == lease
        state.calls.append((operation, payload))
        if state.fail == operation:
            raise RuntimeError("owner unavailable")
        now = int(time.time())
        if operation == "challenge":
            result = {"binding": binding, "nonce": "7" * 64, "expires_at": now + 30}
        elif operation == "channel":
            result = dict(
                binding=binding,
                issued_at=now,
                deadline=now + 30,
                gateway_key=payload["gateway_key"],
                runtime_key=runtime_key,
            )
        elif operation == "register":
            result = dict(
                binding=binding,
                epoch=epoch,
                runtime_key=runtime_key,
                issuer_key=cfg.issuer_key,
                attestation_sha256=digest(payload["record"]),
                expires_at=payload["record"]["expires_at"],
            )
        elif operation == "admit":
            result = payload | {"epoch": epoch}
        elif operation == "start":
            result = dict(
                start_id=start,
                issued_at=now,
                deadline=now + 30,
                max_billable=2064,
                max_record_only=0,
                replayed=False,
            )
        elif operation == "checkpoint":
            state.terminal = payload["record"]
            result = {
                "sequence": state.terminal["sequence"],
                "sha256": digest(state.terminal),
            }
        elif operation == "recover":
            result = dict(
                batch_id=batch,
                terminal_sha256=digest(state.terminal),
                counters=state.terminal["counters"],
                billable=14,
                policy_sha256=POLICY_DIGEST,
            )
        else:
            raise AssertionError(operation)
        result = state.mutate(operation, result)
        record = dict(
            kind="owner-meter-v1",
            operation=operation,
            tenant_id=tenant,
            lease_id=lease,
            gateway_id=gateway,
            request_sha256=digest(payload),
            result=result,
        )
        return signed(owner, record, b"hypermesh-meter-owner-v1\0")

    consumer = Consumer(cfg, SimpleNamespace(trusted_meter=plane), q)
    state.consumer = consumer

    async def attest(config, statement, report):
        assert config == cfg and report == "0" * 2368
        return signed(issuer, statement) | {"snp_report": report}

    consumer.attest = attest

    class FakeGuest:
        runtime_key = runtime.public_key().public_bytes_raw().hex()
        channel = None

        def __init__(self, *args):
            pass

        async def post(self, path, payload):
            state.guest_calls.append((path, payload))
            if path == "/channels/challenge":
                return dict(
                    nonce="8" * 64,
                    runtime_key=self.runtime_key,
                    gateway_key=consumer.gateway_key,
                )
            if path == "/channels/authorize":
                return {"channel": "9" * 64}
            if path == "/quote":
                return {"runtime_key": self.runtime_key, "report": "0" * 2368}
            if path == "/retire":
                persisted = json.loads(
                    q.db.execute("SELECT state FROM trusted_requests").fetchone()[0]
                )
                assert persisted["recovery"] == payload["proof"]
                return {"retired": True}
            assert path == "/execute"
            start_record = dict(
                kind="start-v2",
                binding=binding,
                batch_id=batch,
                epoch=epoch,
                nonce="a" * 64,
            )
            await consumer.exchange(
                dict(
                    binding=binding,
                    operation="start",
                    request=signed(runtime, start_record),
                )
            )
            record = dict(
                kind="checkpoint-v1",
                binding=binding,
                batch_id=batch,
                epoch=epoch,
                start_id=start,
                sequence=1,
                previous_sha256="0" * 64,
                outcome="completed",
                counters=dict(
                    processed_input=5,
                    accepted_output=9,
                    hidden_output=7,
                    cache_hits=0,
                    rejected_speculative=0,
                ),
            )
            record = state.mutate("runtime", record)
            await consumer.exchange(
                dict(
                    binding=binding,
                    operation="checkpoint",
                    request=signed(runtime, record),
                )
            )
            return {
                "outcome": "completed",
                "output_hex": "accepted output".encode().hex(),
            }

    consumer.guest_factory = FakeGuest
    state.cached = SimpleNamespace(
        assigned_gateway_id=gateway,
        device_id=device,
        catalog_id="model",
        client_address="192.0.2.1/32",
        digest_meters=("token_digest_count", "prompt_digest_count"),
    )
    state.payload = {
        "messages": [{"role": "user", "content": "private prompt"}],
        "max_tokens": 16,
    }
    yield state
    q.close()


async def run(s):
    return await s.consumer.execute(
        s.tenant, s.lease, s.cached, s.batch, s.payload, lambda: None
    )


async def test_verified_counts_hidden_once_and_durable_recovery_before_retire(setup):
    s = setup
    result = await run(s)
    assert result.response.json()["usage"] == {
        "prompt_tokens": 5,
        "completion_tokens": 9,
        "total_tokens": 14,
    }
    assert (
        result.response.json()["choices"][0]["message"]["content"] == "accepted output"
    )
    assert s.q.drained(s.tenant, s.lease)
    assert [op for op, _ in s.calls].count("recover") == 1
    assert s.q.db.execute("SELECT count(*) FROM batches").fetchone()[0] == 0
    execute = next(payload for op, payload in s.guest_calls if op == "/execute")
    assert execute["messages"] == s.payload["messages"] and execute["max_tokens"] == 16
    assert (
        b"private prompt" not in s.q.db.serialize()
        and b"accepted output" not in s.q.db.serialize()
    )


@pytest.mark.parametrize(
    "operation,field,value",
    [
        ("channel", "runtime_key", "0" * 64),
        ("channel", "deadline", 0),
        ("register", "epoch", "bad"),
        ("register", "attestation_sha256", "0" * 64),
        ("admit", "max_billable", 9999),
        ("checkpoint", "sha256", "0" * 64),
        ("recover", "billable", 21),
        ("runtime", "previous_sha256", "1" * 64),
        ("runtime", "sequence", 2),
        ("runtime", "epoch", "00000000-0000-4000-8000-000000000001"),
        ("runtime", "start_id", "00000000-0000-4000-8000-000000000002"),
        ("runtime", "batch_id", "00000000-0000-4000-8000-000000000003"),
    ],
)
async def test_conflicting_authority_and_runtime_never_retire(
    setup, operation, field, value
):
    s = setup
    s.mutate = lambda op, result: result | {field: value} if op == operation else result
    with pytest.raises((ValueError, KeyError)):
        await run(s)
    assert s.q.drained(s.tenant, s.lease) == (operation in {"channel", "register"})
    assert not any(op == "/retire" for op, _ in s.guest_calls)


@pytest.mark.parametrize(
    "counters",
    [
        dict(
            processed_input=5,
            accepted_output=9,
            hidden_output=10,
            cache_hits=0,
            rejected_speculative=0,
        ),
        dict(
            processed_input=True,
            accepted_output=9,
            hidden_output=0,
            cache_hits=0,
            rejected_speculative=0,
        ),
        dict(
            processed_input=2049,
            accepted_output=128,
            hidden_output=7,
            cache_hits=0,
            rejected_speculative=0,
        ),
        dict(
            processed_input=5,
            accepted_output=9,
            hidden_output=7,
            cache_hits=1,
            rejected_speculative=1,
        ),
    ],
)
async def test_initial_profile_rejects_invalid_or_unsupported_counts(setup, counters):
    s = setup
    s.mutate = (
        lambda op, result: result | {"counters": counters}
        if op == "runtime"
        else result
    )
    with pytest.raises(ValueError):
        await run(s)
    assert not any(op == "recover" for op, _ in s.calls)


@pytest.mark.parametrize(
    "operation", ["register", "admit", "start", "checkpoint", "recover"]
)
async def test_ambiguous_owner_failure_retains_pending_marker(setup, operation):
    s = setup
    s.fail = operation
    with pytest.raises(RuntimeError):
        await run(s)
    assert s.q.drained(s.tenant, s.lease) == (operation in {"channel", "register"})
    assert not any(op == "/retire" for op, _ in s.guest_calls)


async def test_wrong_workload_refuses_before_guest(setup):
    s = setup
    s.cached.catalog_id = "unapproved"
    with pytest.raises(Refusal, match="workload"):
        await run(s)
    assert not s.guest_calls


async def test_revoked_key_refuses_before_quote(setup):
    s = setup
    s.config.revoked_runtime_keys.append(
        s.runtime.public_key().public_bytes_raw().hex()
    )
    with pytest.raises(Refusal, match="revoked"):
        await run(s)
    assert not any(op == "/quote" for op, _ in s.guest_calls)


async def test_post_admission_fence_never_executes(setup):
    s = setup

    def fence():
        s.q.fence(s.tenant, s.lease)

    with pytest.raises(Refusal, match="fenced"):
        await s.consumer.execute(s.tenant, s.lease, s.cached, s.batch, s.payload, fence)
    assert not any(op == "/execute" for op, _ in s.guest_calls)


@pytest.mark.parametrize(
    "extra",
    [
        {"stream": True},
        {"tools": []},
        {"max_tokens": 129},
        {"temperature": 1},
        {"messages": [{"role": "user", "content": []}]},
    ],
)
def test_payload_restrictions_are_explicit(extra):
    with pytest.raises(ValueError):
        execution_payload(
            {"messages": [{"role": "user", "content": "x"}], "max_tokens": 1} | extra
        )


async def test_legacy_provider_totals_cannot_flush_in_verified_mode(tmp_path):
    q = DigestQueue(tmp_path / "legacy.db")
    tenant, lease = uuid.uuid4(), uuid.uuid4()
    batch = q.begin(tenant, lease, ["token_digest_count"])
    q.finish(batch, 999999)
    plane = SimpleNamespace(post_reading=AsyncMock())
    await q.flush(plane, verified_only=True)
    plane.post_reading.assert_not_awaited()
    assert not q.drained(tenant, lease)
    q.close()


async def test_report_verifier_and_independent_issuer_are_both_required(
    setup, monkeypatch
):
    s = setup
    now = int(time.time())
    statement = dict(
        kind="attestation-v1",
        issuer=s.config.issuer,
        binding=s.binding,
        nonce="7" * 64,
        runtime_key=s.runtime.public_key().public_bytes_raw().hex(),
        issued_at=now,
        expires_at=now + 60,
        platform="sev-snp-cpu",
        chain_valid=True,
        tcb_current=True,
        revocation_checked=True,
        debug_disabled=True,
        workload_measured=True,
        protected_time=True,
        rollback_protected=True,
    )
    calls = []

    async def command(binary, args, raw, **kw):
        calls.append((binary, args, raw))
        return canonical(signed(s.issuer, statement))

    monkeypatch.setattr(policy, "command", command)
    submission = await policy.attest(s.config, statement, "0" * 2368)
    assert submission["record"] == statement and len(calls) == 2
    assert "-check_crl=true" in calls[0][1] and "-network=true" in calls[0][1]
    assert any(a.startswith("-report_data=") for a in calls[0][1])
    assert calls[1][0] == s.config.issuer_command
    bad = signed(s.runtime, statement)
    monkeypatch.setattr(policy, "command", AsyncMock(return_value=canonical(bad)))
    with pytest.raises(Refusal, match="signature"):
        await policy.attest(s.config, statement, "0" * 2368)


async def test_forged_runtime_relay_cannot_forward_owner_operations(setup):
    s = setup
    state = {
        "runtime_key": s.runtime.public_key().public_bytes_raw().hex(),
        "session": {"epoch": s.epoch},
    }
    s.consumer.active[(s.tenant, s.lease, s.batch)] = {
        "binding": s.binding,
        "config": s.config,
        "state": state,
        "lock": asyncio.Lock(),
    }
    record = dict(
        kind="start-v2",
        binding=s.binding,
        epoch=s.epoch,
        batch_id=s.batch,
        nonce="a" * 64,
    )
    bad = signed(Ed25519PrivateKey.generate(), record)
    with pytest.raises(Refusal, match="signature"):
        await s.consumer.exchange(
            {"binding": s.binding, "operation": "start", "request": bad}
        )
    assert not s.calls


def test_owner_signatures_bind_full_request_and_tenant(setup):
    s = setup
    payload = {"batch_id": s.batch}
    record = dict(
        kind="owner-meter-v1",
        operation="recover",
        tenant_id=s.tenant,
        lease_id=s.lease,
        gateway_id=s.binding["gateway_id"],
        request_sha256=digest(payload),
        result={},
    )
    proof = signed(s.owner, record, b"hypermesh-meter-owner-v1\0")
    from hypermesh_gateway_service.trusted_meter.authority import owner_reply

    args = (
        s.config.owner_key,
        "recover",
        payload,
        s.tenant,
        s.lease,
        s.binding["gateway_id"],
    )
    assert owner_reply(proof, *args) == {}
    with pytest.raises(Refusal, match="scope"):
        owner_reply(
            proof,
            s.config.owner_key,
            "recover",
            {"batch_id": str(uuid.uuid4())},
            s.tenant,
            s.lease,
            s.binding["gateway_id"],
        )
    proof["record"]["result"] = {"billable": 9999}
    with pytest.raises(Refusal, match="signature"):
        owner_reply(proof, *args)


async def test_changed_approved_binary_is_never_executed(tmp_path):
    binary = tmp_path / "issuer"
    binary.write_bytes(b"not executable")
    with pytest.raises(Refusal, match="binary"):
        await policy.command(
            policy.Binary(executable=str(binary), sha256="0" * 64), [], b"{}"
        )
