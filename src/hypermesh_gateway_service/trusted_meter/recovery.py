"""Owner-authorized restart repair. No caller quantities or inference retries."""

import asyncio
import time
from uuid import UUID
from typing import Literal
from pydantic import Field
from . import policy
from .authority import owner_reply
from .client import require
from .wire import (
    Wire,
    Channel,
    Binding,
    Signed,
    Attestation,
    Checkpoint,
    Counters,
    Digest,
    verify,
    digest,
    POLICY_DIGEST,
)

ZERO = "0" * 64


class Entry(Wire):
    batch_id: UUID
    epoch: UUID
    phase: Literal["starting", "running", "terminal"]
    start_id: str = Field(max_length=36)
    records: list[Signed] = Field(max_length=256)


class HistoryChallenge(Channel):
    batch_id: UUID
    historical_runtime_key: Digest


def check_entry(raw, state, authority):
    entry = Entry.model_validate(raw)
    require(
        str(entry.batch_id) == state["batch_id"]
        and str(entry.epoch) == state["session"]["epoch"],
        "history_scope",
    )
    start = authority["start"]
    if entry.phase == "starting":
        require(entry.start_id == "" and not entry.records, "history_start")
    else:
        require(
            start is not None and entry.start_id == start["start_id"], "history_start"
        )
    previous, counts = ZERO, {k: 0 for k in Counters.model_fields}
    anchors = authority["checkpoints"]
    require(len(entry.records) >= len(anchors), "history_missing_anchor")
    for index, signed in enumerate(entry.records, 1):
        record = verify(signed, Checkpoint, state["runtime_key"])
        require(
            record.binding.model_dump(mode="json") == state["binding"]
            and str(record.batch_id) == state["batch_id"]
            and str(record.epoch) == state["session"]["epoch"]
            and str(record.start_id) == entry.start_id,
            "history_record_scope",
        )
        require(
            record.sequence == index and record.previous_sha256 == previous,
            "history_chain",
        )
        values = record.counters.model_dump()
        require(all(values[k] >= counts[k] for k in values), "counter_regression")
        require(
            record.counters.billable <= authority["max_billable"]
            and values["cache_hits"] + values["rejected_speculative"]
            <= authority["max_record_only"],
            "counter_budget",
        )
        require(
            record.outcome != "no_work" or not any(values.values()), "invalid_no_work"
        )
        require(
            index == len(entry.records) or record.outcome == "running",
            "history_after_terminal",
        )
        if index == len(entry.records):
            require(
                (entry.phase == "terminal") == (record.outcome != "running"),
                "history_phase",
            )
        previous, counts = digest(record), values
        if index <= len(anchors):
            require(
                anchors[index - 1]["sha256"] == previous
                and anchors[index - 1]["signature"] == signed.signature,
                "history_anchor_conflict",
            )
    require(entry.phase != "terminal" or bool(entry.records), "history_empty_terminal")
    return entry.model_dump(mode="json")


def original_session(state):
    b = Binding.model_validate(state["binding"]).model_dump(mode="json")
    session = owner_reply(
        state["session_proof"],
        state["owner_key"],
        "register",
        state["attestation"],
        b["tenant_id"],
        b["lease_id"],
        b["gateway_id"],
    )
    require(
        session == state["session"]
        and session["binding"] == b
        and session["runtime_key"] == state["runtime_key"],
        "original_session",
    )
    submission = state["attestation"]
    attestation = verify(
        Signed.model_validate({k: submission[k] for k in ("record", "signature")}),
        Attestation,
        session["issuer_key"],
    )
    require(
        digest(attestation) == session["attestation_sha256"]
        and attestation.runtime_key == state["runtime_key"]
        and attestation.binding.model_dump(mode="json") == b,
        "original_attestation",
    )
    return b


async def history_channel(consumer, guest, context):
    state = context["state"]
    scope = dict(
        batch_id=state["batch_id"], historical_runtime_key=state["runtime_key"]
    )
    request = HistoryChallenge.model_validate(
        await guest.post("/history/channels/challenge", scope)
    ).model_dump(mode="json")
    require(
        all(request[k] == v for k, v in scope.items())
        and request["runtime_key"] == guest.runtime_key
        and request["gateway_key"] == consumer.gateway_key,
        "history_channel_scope",
    )
    before = time.monotonic()
    proof, result = await consumer.owner(context, "history-channel", request)
    issued, deadline = result.get("issued_at"), result.get("deadline")
    expected = dict(
        binding=context["binding"],
        **scope,
        runtime_key=guest.runtime_key,
        gateway_key=consumer.gateway_key,
        issued_at=issued,
        deadline=deadline,
        permissions=["status", "retire"],
    )
    require(
        result == expected
        and type(issued) is int
        and type(deadline) is int
        and issued <= time.time() < deadline
        and 0 < deadline - issued <= 30
        and time.monotonic() - before < deadline - issued - 1,
        "history_channel_expired",
    )
    reply = await guest.post(
        "/history/channels/authorize", {"nonce": request["nonce"], "proof": proof}
    )
    require(
        isinstance(reply, dict)
        and set(reply) == {"channel"}
        and isinstance(reply["channel"], str)
        and len(reply["channel"]) == 64
        and all(c in "0123456789abcdef" for c in reply["channel"]),
        "channel_token",
    )
    guest.channel = reply["channel"]


async def repair(consumer, tenant, lease, batch, gateway, cached=None):
    identity = (str(tenant), str(lease))
    require(
        identity not in consumer.leases and len(consumer.leases) < 64,
        "trusted_runtime_busy",
    )
    consumer.leases.add(identity)
    try:
        async with asyncio.timeout(60):
            return await reconcile(consumer, tenant, lease, str(batch), gateway, cached)
    finally:
        consumer.leases.discard(identity)


async def reconcile(consumer, tenant, lease, batch, gateway, cached):
    state = consumer.journal.load(tenant, lease, batch)
    if state is None:
        # Pre-trusted provider totals have no independently verified identity.
        # Keep the queue and drain fence intact; never manufacture a trusted row.
        return {"batch_id": batch, "status": "legacy_unverified", "pending": True}
    b = original_session(state)
    require(
        b["tenant_id"] == str(tenant)
        and b["lease_id"] == str(lease)
        and b["gateway_id"] == str(gateway)
        and state["batch_id"] == batch,
        "repair_scope",
    )
    context = {"binding": b, "state": state, "config": policy.configured_history()}
    lookup = dict(batch_id=batch, runtime_key=state["runtime_key"])
    proof, history = await consumer.owner(context, "history-read", lookup)
    require(
        history["binding"] == b
        and history["batch_id"] == batch
        and history["runtime_key"] == state["runtime_key"]
        and history["runtime_session"] == state["session"],
        "owner_history_scope",
    )
    row = history["authority"]
    require(
        row["epoch"] == state["session"]["epoch"]
        and all(
            row[k] == state["admission"][k]
            for k in ("max_billable", "max_record_only", "meters")
        ),
        "owner_admission_scope",
    )
    if state.get("locally_retired") and state["phase"] == "disputed":
        require(
            row.get("dispute") is not None
            and row["dispute"]["entry"] == state["archive"],
            "retired_archive_conflict",
        )
        check_entry(row["dispute"]["entry"], state, row)
        return {"batch_id": batch, "status": "disputed", "pending": True}
    if state.get("locally_retired"):
        require(
            row["recovered"]
            and row["terminal"] is not None
            and row["terminal"]["sha256"]
            == state["recovery"]["record"]["result"]["terminal_sha256"],
            "retired_owner_conflict",
        )
        return {"batch_id": batch, "status": "recovered", "pending": False}
    # Retain the signed owner observation before any remote deletion.
    state["history_proof"] = proof
    consumer.journal.save(batch, state)
    guest = None
    address = state.get("guest_address")
    if cached is not None:
        require(
            str(cached.device_id) == b["device_id"]
            and str(cached.assigned_gateway_id) == b["gateway_id"],
            "repair_host_scope",
        )
        address = cached.client_address
    if address:
        guest = consumer.guest_factory(
            address, context["config"].guest_port, consumer.client_tls
        )
    terminal = row["terminal"]
    if row["start"] is None and not row.get("dispute"):
        zero = {k: 0 for k in Counters.model_fields}
        no_start = dict(
            kind="owner-no-start-v1",
            binding=b,
            epoch=row["epoch"],
            batch_id=batch,
            counters=zero,
            outcome="no_work",
        )
        cancellation, result = await consumer.owner(
            context, "cancel", {"batch_id": batch}
        )
        require(
            result == {"batch_id": batch, "terminal_sha256": digest(no_start)},
            "cancellation_scope",
        )
        committed, result = await consumer.owner(
            context, "history-recover", lookup | {"terminal_sha256": digest(no_start)}
        )
        require(
            result
            == dict(
                batch_id=batch,
                terminal_sha256=digest(no_start),
                counters=zero,
                billable=0,
                policy_sha256=POLICY_DIGEST,
            ),
            "no_start_recovery_scope",
        )
        state.update(
            phase="recovered",
            recovery=committed,
            recovery_operation="history-recover",
            cancellation=cancellation,
        )
        consumer.journal.save(batch, state)
        recovery, operation = cancellation, "cancel"
    elif terminal is not None:
        # Verify the entire stored signed chain independently of transport.
        require(
            terminal["record"].get("kind") == "checkpoint-v1", "owner_terminal_kind"
        )
        records = [
            {"record": a["record"], "signature": a["signature"]}
            for a in row["checkpoints"]
        ]
        require(
            bool(records) and terminal == row["checkpoints"][-1],
            "owner_terminal_anchor",
        )
        entry = check_entry(
            dict(
                batch_id=batch,
                epoch=row["epoch"],
                phase="terminal",
                start_id=row["start"]["start_id"],
                records=records,
            ),
            state,
            row,
        )
        final = Checkpoint.model_validate(entry["records"][-1]["record"])
        payload = lookup | {"terminal_sha256": digest(final)}
        recovery, result = await consumer.owner(context, "history-recover", payload)
        require(
            result
            == dict(
                batch_id=batch,
                terminal_sha256=digest(final),
                counters=final.counters.model_dump(),
                billable=final.counters.billable,
                policy_sha256=POLICY_DIGEST,
            ),
            "recovery_scope",
        )
        state.update(
            phase="recovered", recovery=recovery, recovery_operation="history-recover"
        )
        consumer.journal.save(batch, state)
        operation = "history-recover"
    elif row.get("dispute"):
        archive = row["dispute"]
        entry = check_entry(archive["entry"], state, row)
        recovery = await archive_proof(consumer, context, lookup, entry, row)
        operation = "archive-dispute"
    else:
        if guest is None:
            return {"batch_id": batch, "status": "missing_history", "pending": True}
        await history_channel(consumer, guest, context)
        entry = check_entry(await guest.post("/status", lookup), state, row)
        recovery = await archive_proof(consumer, context, lookup, entry, row)
        operation = "archive-dispute"
    if guest is None:
        return {"batch_id": batch, "status": state["phase"], "pending": True}
    await history_channel(consumer, guest, context)
    reply = await guest.post(
        "/retire", lookup | {"operation": operation, "proof": recovery}
    )
    require(reply == {"retired": True}, "retirement_reply")
    if operation in {"history-recover", "cancel"}:
        consumer.journal.retired(batch)
        return {"batch_id": batch, "status": "recovered", "pending": False}
    state["phase"] = "disputed"
    state["guest_retired"] = True
    consumer.journal.save(batch, state)
    consumer.journal.retired(batch)
    return {"batch_id": batch, "status": "disputed", "pending": True}


async def archive_proof(consumer, context, lookup, entry, row):
    state, b = context["state"], context["binding"]
    raw = await consumer.plane.trusted_meter(
        b["tenant_id"], b["lease_id"], "archive-dispute", lookup | {"entry": entry}
    )
    result = owner_reply(
        raw,
        context["config"].owner_key,
        "archive-dispute",
        lookup,
        b["tenant_id"],
        b["lease_id"],
        b["gateway_id"],
    )
    last = digest(entry["records"][-1]["record"]) if entry["records"] else ZERO
    manifest = dict(
        kind="archived-dispute-v1",
        binding=b,
        **lookup,
        epoch=entry["epoch"],
        start_id=entry["start_id"],
        phase=entry["phase"],
        sequence=len(entry["records"]),
        last_record_sha256=last,
    )
    anchors = row["checkpoints"]
    require(
        result
        == dict(
            **lookup,
            archive_sha256=digest(manifest),
            last_anchor_sequence=len(anchors),
            last_anchor_sha256=anchors[-1]["sha256"] if anchors else ZERO,
            status="disputed",
        ),
        "archive_scope",
    )
    state.update(
        phase="disputed",
        recovery=raw,
        recovery_operation="archive-dispute",
        archive=entry,
    )
    consumer.journal.save(state["batch_id"], state)
    return raw
