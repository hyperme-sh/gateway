"""Restart repair contracts using signed owner and guest doubles."""

from copy import deepcopy
from types import SimpleNamespace
import time
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_trusted_meter import run, signed

from hypermesh_gateway_service.trusted_meter import policy
from hypermesh_gateway_service.trusted_meter.client import Consumer
from hypermesh_gateway_service.trusted_meter.wire import digest, Refusal


pytest_plugins = ["test_trusted_meter"]


async def prepare(s, monkeypatch, *, terminal=True):
    s.fail = "recover"
    with pytest.raises(RuntimeError):
        await run(s)
    saved = s.consumer.journal.load(s.tenant, s.lease, s.batch)
    records = saved["records"]
    anchors = [
        dict(
            record=r["record"],
            signature=r["signature"],
            sha256=digest(r["record"]),
            counters=r["record"]["counters"],
            anchored_at=1000,
        )
        for r in records
    ]
    row = dict(
        epoch=s.epoch,
        max_billable=saved["admission"]["max_billable"],
        max_record_only=0,
        meters=saved["admission"]["meters"],
        start=saved["start"],
        checkpoints=anchors if terminal else [],
        terminal=anchors[-1] if terminal else None,
        recovered=False,
        renewals=[],
    )
    s.history = dict(
        batch_id=s.batch,
        runtime_key=saved["runtime_key"],
        binding=s.binding,
        runtime_session=saved["session"],
        status="pending",
        authority=row,
    )
    s.entry = dict(
        batch_id=s.batch,
        epoch=s.epoch,
        start_id=s.start,
        phase="terminal",
        records=records,
    )
    s.repair_calls = []
    s.retire_fail = False
    s.mutate_history = lambda value: value
    s.mutate_result = lambda op, value: value
    monkeypatch.setattr(
        policy,
        "configured_history",
        lambda: s.config.model_copy(
            update={
                "profiles": {},
                "policy_expires_at": 1,
                "revoked_runtime_keys": [saved["runtime_key"]],
            }
        ),
    )

    async def plane(tenant, lease, operation, payload):
        s.repair_calls.append((operation, payload))
        if operation == "history-read":
            result = s.mutate_history(deepcopy(s.history))
        elif operation == "history-channel":
            result = dict(
                binding=s.binding,
                batch_id=s.batch,
                historical_runtime_key=saved["runtime_key"],
                runtime_key=payload["runtime_key"],
                gateway_key=payload["gateway_key"],
                issued_at=int(time.time()),
                deadline=int(time.time()) + 30,
                permissions=["status", "retire"],
            )
        elif operation == "cancel":
            assert row["start"] is None
            no_start = dict(
                kind="owner-no-start-v1",
                binding=s.binding,
                epoch=s.epoch,
                batch_id=s.batch,
                counters={k: 0 for k in anchors[-1]["counters"]},
                outcome="no_work",
            )
            row["terminal"] = dict(
                record=no_start, sha256=digest(no_start), counters=no_start["counters"]
            )
            result = dict(batch_id=s.batch, terminal_sha256=digest(no_start))
        elif operation == "history-recover":
            row["recovered"] = True
            result = dict(
                batch_id=s.batch,
                terminal_sha256=row["terminal"]["sha256"],
                counters=row["terminal"]["counters"],
                billable=14 if row["start"] else 0,
                policy_sha256=s.binding["policy_sha256"],
            )
        elif operation == "archive-dispute":
            e = payload["entry"]
            manifest = dict(
                kind="archived-dispute-v1",
                binding=s.binding,
                batch_id=s.batch,
                runtime_key=saved["runtime_key"],
                epoch=e["epoch"],
                start_id=e["start_id"],
                phase=e["phase"],
                sequence=len(e["records"]),
                last_record_sha256=digest(e["records"][-1]["record"])
                if e["records"]
                else "0" * 64,
            )
            result = dict(
                batch_id=s.batch,
                runtime_key=saved["runtime_key"],
                archive_sha256=digest(manifest),
                last_anchor_sequence=len(row["checkpoints"]),
                last_anchor_sha256=row["checkpoints"][-1]["sha256"]
                if row["checkpoints"]
                else "0" * 64,
                status="disputed",
            )
            row["dispute"] = {"entry": e, "result": result}
            payload = {k: payload[k] for k in ("batch_id", "runtime_key")}
        else:
            raise AssertionError(operation)
        result = s.mutate_result(operation, result)
        return signed(
            s.owner,
            dict(
                kind="owner-meter-v1",
                operation=operation,
                tenant_id=s.tenant,
                lease_id=s.lease,
                gateway_id=s.binding["gateway_id"],
                request_sha256=digest(payload),
                result=result,
            ),
            b"hypermesh-meter-owner-v1\0",
        )

    # Recreate the consumer to model a process restart and new Gateway TLS key.
    consumer = Consumer(s.config, SimpleNamespace(trusted_meter=plane), s.q)
    new_guest = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

    class Guest:
        runtime_key = new_guest
        channel = None

        def __init__(self, *args):
            pass

        async def post(self, path, payload):
            s.repair_calls.append((path, payload))
            if path == "/history/channels/challenge":
                return payload | dict(
                    nonce="f" * 64,
                    runtime_key=new_guest,
                    gateway_key=consumer.gateway_key,
                )
            if path == "/history/channels/authorize":
                return {"channel": "e" * 64}
            if path == "/status":
                return deepcopy(s.entry)
            if path == "/retire":
                state = consumer.journal.load(s.tenant, s.lease, s.batch)
                assert (
                    state[
                        "cancellation"
                        if payload["operation"] == "cancel"
                        else "recovery"
                    ]
                    == payload["proof"]
                )
                if s.retire_fail:
                    raise RuntimeError("lost retirement acknowledgement")
                return {"retired": True}
            raise AssertionError(path)

    consumer.guest_factory = Guest
    s.consumer = consumer
    return saved


async def repair(s, **changes):
    args = dict(
        tenant=s.tenant,
        lease=s.lease,
        batch=s.batch,
        gateway=s.binding["gateway_id"],
        cached=s.cached,
    )
    return await s.consumer.repair(**(args | changes))


async def test_restart_revoked_trust_new_guest_and_repeated_repair(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch)
    s.q.fence(s.tenant, s.lease)
    result = await repair(s)
    assert result == {"batch_id": s.batch, "status": "recovered", "pending": False}
    assert s.q.drained(s.tenant, s.lease) and s.q.fenced(s.tenant, s.lease)
    assert await repair(s) == result
    assert s.q.db.execute("SELECT count(*) FROM trusted_repairs").fetchone()[0] == 1
    assert not any(
        op in {"admit", "start", "checkpoint", "/execute", "/quote"}
        for op, _ in s.repair_calls
    )
    assert b"private prompt" not in s.q.db.serialize()


async def test_lost_retirement_ack_keeps_committed_proof(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch)
    s.retire_fail = True
    with pytest.raises(RuntimeError):
        await repair(s)
    assert not s.q.drained(s.tenant, s.lease)
    state = s.consumer.journal.load(s.tenant, s.lease, s.batch)
    assert state["phase"] == "recovered" and state["recovery"]
    s.retire_fail = False
    assert (await repair(s))["pending"] is False


async def test_unanchored_terminal_archives_without_charging(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch, terminal=False)
    result = await repair(s)
    assert result["status"] == "disputed" and result["pending"]
    assert not s.q.drained(s.tenant, s.lease)
    assert not any(op == "history-recover" for op, _ in s.repair_calls)
    state = s.consumer.journal.load(s.tenant, s.lease, s.batch)
    assert state["archive"] == s.entry and state["guest_retired"]
    assert (await repair(s)) == result


@pytest.mark.parametrize("field", ["tenant", "lease", "batch", "gateway"])
async def test_repair_scope_rejected(setup, monkeypatch, field):
    s = setup
    await prepare(s, monkeypatch)
    with pytest.raises(Refusal):
        await repair(s, **{field: str(uuid.uuid4())})
    assert not s.q.drained(s.tenant, s.lease)


@pytest.mark.parametrize(
    "field", ["runtime_key", "batch_id", "binding", "runtime_session"]
)
async def test_wrong_owner_history_rejected(setup, monkeypatch, field):
    s = setup
    await prepare(s, monkeypatch)
    s.mutate_history = lambda value: value | {field: None}
    with pytest.raises(Refusal):
        await repair(s)
    assert not any(op == "/retire" for op, _ in s.repair_calls)


async def test_bad_runtime_chain_never_settles(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch)
    s.history["authority"]["checkpoints"][0]["signature"] = "0" * 128
    with pytest.raises(Refusal):
        await repair(s)
    assert not any(op == "history-recover" for op, _ in s.repair_calls)


async def test_capacity_or_archive_failure_keeps_local_history(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch, terminal=False)

    def fail(op, result):
        if op == "archive-dispute":
            raise RuntimeError("capacity refused")
        return result

    s.mutate_result = fail
    with pytest.raises(RuntimeError):
        await repair(s)
    assert not s.q.drained(s.tenant, s.lease)
    assert not any(op == "/retire" for op, _ in s.repair_calls)


async def test_legacy_provider_quantity_is_not_repaired_as_trusted(setup):
    s = setup
    s.q.finish(s.batch, 999)
    assert await repair(s) == {
        "batch_id": s.batch,
        "status": "legacy_unverified",
        "pending": True,
    }
    assert not s.q.drained(s.tenant, s.lease)


async def test_repair_endpoint_requires_service_auth_and_rejects_counts(setup):
    from unittest.mock import AsyncMock
    from fastapi import HTTPException
    from hypermesh_gateway_service.routes import repair_digest

    s = setup
    consumer = SimpleNamespace(repair=AsyncMock(return_value={"pending": True}))
    state = SimpleNamespace(
        gateway_service_secret="unit-secret",
        trusted_meter=consumer,
        ticket_cache=SimpleNamespace(get=lambda *a: s.cached),
        control_plane=SimpleNamespace(
            gateway_identity=AsyncMock(return_value=s.binding["gateway_id"])
        ),
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=state),
        headers={"X-Tenant-ID": s.tenant},
        body=AsyncMock(return_value=b""),
    )
    with pytest.raises(HTTPException) as err:
        await repair_digest(request, uuid.UUID(s.lease), uuid.UUID(s.batch))
    assert err.value.status_code == 401
    request.headers["Authorization"] = "Bearer unit-secret"
    request.body.return_value = b'{"quantity":0}'
    with pytest.raises(HTTPException) as err:
        await repair_digest(request, uuid.UUID(s.lease), uuid.UUID(s.batch))
    assert err.value.status_code == 400
    consumer.repair.assert_not_awaited()
    request.body.return_value = b""
    assert await repair_digest(request, uuid.UUID(s.lease), uuid.UUID(s.batch)) == {
        "pending": True
    }


async def test_repair_excludes_live_execution(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch)
    s.consumer.leases.add((s.tenant, s.lease))
    with pytest.raises(Refusal, match="busy"):
        await repair(s)
    assert not s.repair_calls


async def test_conflicting_guest_history_keeps_archive_and_retirement_off(
    setup, monkeypatch
):
    s = setup
    await prepare(s, monkeypatch, terminal=False)
    s.entry["records"][0]["signature"] = "0" * 128
    with pytest.raises(Refusal):
        await repair(s)
    assert not any(op in {"archive-dispute", "/retire"} for op, _ in s.repair_calls)


async def test_missing_guest_keeps_pending_but_commits_owner_recovery(
    setup, monkeypatch
):
    s = setup
    await prepare(s, monkeypatch)
    state = s.consumer.journal.load(s.tenant, s.lease, s.batch)
    state.pop("guest_address")
    s.consumer.journal.save(s.batch, state)
    assert (await repair(s, cached=None))["pending"]
    assert s.consumer.journal.load(s.tenant, s.lease, s.batch)["phase"] == "recovered"


async def test_atomic_retirement_rolls_back_on_audit_failure(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch)
    s.q.db.execute(
        "CREATE TRIGGER refuse_audit BEFORE INSERT ON trusted_repairs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"
    )
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        await repair(s)
    assert not s.q.drained(s.tenant, s.lease)
    assert s.consumer.journal.load(s.tenant, s.lease, s.batch)["recovery"]
    s.q.db.execute("DROP TRIGGER refuse_audit")
    assert not (await repair(s))["pending"]


def test_history_configuration_can_read_expired_policy_but_execution_cannot(
    setup, tmp_path, monkeypatch
):
    s = setup
    # Undo the fixture's execution configuration double for this contract.
    import importlib

    module = importlib.reload(policy)
    path = tmp_path / "policy.json"
    path.write_text(
        s.config.model_copy(
            update={"profiles": {}, "policy_expires_at": 1}
        ).model_dump_json()
    )
    monkeypatch.setenv("HYPERMESH_TRUSTED_METER_CONFIG", str(path))
    assert module.configured_history().profiles == {}
    with pytest.raises(Refusal, match="expired"):
        module.configured()


async def test_no_start_requires_owner_cancellation_then_zero_commit(
    setup, monkeypatch
):
    s = setup
    await prepare(s, monkeypatch)
    row = s.history["authority"]
    row.update(start=None, checkpoints=[], terminal=None)
    assert not (await repair(s))["pending"]
    calls = [op for op, _ in s.repair_calls]
    assert (
        calls.index("cancel") < calls.index("history-recover") < calls.index("/retire")
    )
    assert (
        next(payload for op, payload in s.repair_calls if op == "/retire")["operation"]
        == "cancel"
    )


async def test_no_start_refusal_never_becomes_zero(setup, monkeypatch):
    s = setup
    await prepare(s, monkeypatch)
    s.history["authority"].update(start=None, checkpoints=[], terminal=None)

    def refuse(op, result):
        if op == "cancel":
            raise Refusal("runtime_key_revoked")
        return result

    s.mutate_result = refuse
    with pytest.raises(Refusal):
        await repair(s)
    assert not s.q.drained(s.tenant, s.lease)
    assert not any(op == "history-recover" for op, _ in s.repair_calls)


def test_retired_disputes_free_active_capacity_but_block_drain(setup):
    s = setup
    s.q.discard_unstarted(s.batch)
    for _ in range(300):
        batch = s.q.begin(s.tenant, s.lease, ["token_digest_count"])
        state = {
            "binding": s.binding,
            "batch_id": batch,
            "phase": "disputed",
            "recovery": {"signed_archive": "unit"},
        }
        s.consumer.journal.save(batch, state)
        s.consumer.journal.retired(batch)
    assert s.q.db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
    assert s.q.db.execute("SELECT count(*) FROM trusted_repairs").fetchone()[0] == 300
    assert not s.q.drained(s.tenant, s.lease)
    assert s.q.drained(str(uuid.uuid4()), s.lease)


def test_retention_isolated_by_organization_and_reclaims_only_completed(
    setup, monkeypatch
):
    from hypermesh_gateway_service.trusted_meter import journal

    s = setup
    monkeypatch.setattr(journal, "MAX_ORGANIZATION_HISTORY", 2)
    s.q.discard_unstarted(s.batch)

    def add(org, phase, retired=True):
        batch = s.q.begin(s.tenant, s.lease, ["token_digest_count"], organization=org)
        state = {
            "binding": s.binding,
            "batch_id": batch,
            "phase": phase,
            "recovery": {"signed_owner": "unit"},
        }
        s.consumer.journal.save(batch, state)
        if retired:
            s.consumer.journal.retired(batch)
        return batch

    unresolved = add("org-a", "disputed")
    complete = add("org-a", "recovered")
    replacement = add("org-a", "recovered")
    assert not s.q.db.execute(
        "SELECT 1 FROM trusted_repairs WHERE id=?", (complete,)
    ).fetchone()
    assert s.q.db.execute(
        "SELECT 1 FROM trusted_repairs WHERE id=?", (unresolved,)
    ).fetchone()
    # Another organization gets its own allocation despite org-a being full.
    other = add("org-b", "disputed")
    assert (
        s.q.db.execute(
            "SELECT organization FROM trusted_repairs WHERE id=?", (other,)
        ).fetchone()[0]
        == "org-b"
    )
    add("org-a", "disputed")  # Reclaims the completed replacement, not a dispute.
    assert not s.q.db.execute(
        "SELECT 1 FROM trusted_repairs WHERE id=?", (replacement,)
    ).fetchone()
    with pytest.raises(Refusal, match="capacity"):
        add("org-a", "admitted", retired=False)
    assert s.q.db.execute(
        "SELECT 1 FROM trusted_repairs WHERE id=?", (other,)
    ).fetchone()
    assert not s.q.drained(s.tenant, s.lease)
    assert add("org-b", "recovered")
