"""Trusted CPU consumer; ambiguous work stays durable for the recovery slice."""

import asyncio
import time
import uuid
import httpx
from pydantic import Field
from . import policy
from .authority import owner_reply
from .journal import Journal
from .transport import Guest, Relay, contexts
from .wire import (
    Wire,
    Binding,
    Channel,
    Signed,
    FreshStart,
    FreshRenewal,
    Checkpoint,
    Refusal,
    verify,
    digest,
    canonical,
    POLICY_DIGEST,
)
from hypermesh_gateway_service.chat import ProxiedChat


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


class Message(Wire):
    role: str = Field(pattern=r"^(system|user|assistant)$")
    content: str = Field(max_length=60000)


def execution_payload(payload):
    allowed = {"lease_id", "model", "messages", "max_tokens", "stream", "temperature"}
    require(set(payload) <= allowed, "unsupported_generation_options")
    require(payload.get("stream", False) is False, "trusted_streaming_unsupported")
    require(
        type(payload.get("max_tokens")) is int and 1 <= payload["max_tokens"] <= 128,
        "trusted_max_tokens_required",
    )
    require(payload.get("temperature", 0) == 0, "trusted_greedy_only")
    messages = payload.get("messages")
    require(isinstance(messages, list) and 1 <= len(messages) <= 64, "invalid_messages")
    messages = [Message.model_validate(m).model_dump() for m in messages]
    result = {"messages": messages, "max_tokens": payload["max_tokens"]}
    require(len(canonical(result)) <= 60000, "request_oversized")
    return result


class Consumer:
    def __init__(self, config, plane, queue):
        self.config, self.plane, self.queue = config, plane, queue
        self.journal = Journal(queue)
        self.gateway_key, self.client_tls, server_tls = contexts()
        self.relay = Relay(config, server_tls, self.exchange)
        self.active = {}
        self.leases = set()
        self.guest_factory = Guest
        self.attest = policy.attest

    async def repair(self, tenant, lease, batch, gateway, cached=None):
        from .recovery import repair

        return await repair(self, tenant, lease, batch, gateway, cached)

    async def start(self):
        await self.relay.start()

    async def close(self):
        await self.relay.close()

    async def owner(self, context, operation, payload):
        b, config = context["binding"], context["config"]
        raw = await self.plane.trusted_meter(
            b["tenant_id"], b["lease_id"], operation, payload
        )
        result = owner_reply(
            raw,
            config.owner_key,
            operation,
            payload,
            b["tenant_id"],
            b["lease_id"],
            b["gateway_id"],
        )
        return raw, result

    async def channel(self, guest, context):
        request = Channel.model_validate(
            await guest.post("/channels/challenge", {})
        ).model_dump(mode="json")
        require(
            request["runtime_key"] == guest.runtime_key
            and request["gateway_key"] == self.gateway_key,
            "channel_key_mismatch",
        )
        require(
            guest.runtime_key not in context["config"].revoked_runtime_keys,
            "runtime_revoked",
        )
        before = time.monotonic()
        proof, result = await self.owner(context, "channel", request)
        require(
            set(result)
            == {"binding", "issued_at", "deadline", "gateway_key", "runtime_key"},
            "channel_fields",
        )
        require(
            result["binding"] == context["binding"]
            and result["gateway_key"] == self.gateway_key
            and result["runtime_key"] == guest.runtime_key,
            "channel_scope",
        )
        issued, deadline = result["issued_at"], result["deadline"]
        require(
            type(issued) is int
            and type(deadline) is int
            and issued <= time.time() < deadline
            and 0 < deadline - issued <= 30
            and time.monotonic() - before < deadline - issued - 1,
            "channel_expired",
        )
        reply = await guest.post(
            "/channels/authorize", {"nonce": request["nonce"], "proof": proof}
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

    async def execute(self, tenant, lease, cached, batch, payload, recheck):
        try:
            return await self._execute(tenant, lease, cached, batch, payload, recheck)
        finally:
            # Before this durable marker, only channel/quote/session setup can
            # have occurred. No admission or execution has been sent.
            if not self.queue.db.execute(
                "SELECT 1 FROM trusted_requests WHERE id=?", (batch,)
            ).fetchone():
                self.queue.discard_unstarted(batch)

    async def _execute(self, tenant, lease, cached, batch, payload, recheck):
        work = execution_payload(payload)
        config = policy.configured()
        require(
            (config.relay_bind, config.relay_port, config.relay_url)
            == (self.config.relay_bind, self.config.relay_port, self.config.relay_url),
            "relay_config_changed",
        )
        identity = (str(tenant), str(lease))
        require(
            identity not in self.leases and len(self.leases) < 64,
            "trusted_runtime_busy",
        )
        self.leases.add(identity)
        context = None
        try:
            scope = {
                "tenant_id": str(tenant),
                "lease_id": str(lease),
                "gateway_id": str(cached.assigned_gateway_id),
            }
            raw = await self.plane.trusted_meter(tenant, lease, "challenge", None)
            challenge = owner_reply(
                raw,
                config.owner_key,
                "challenge",
                None,
                tenant,
                lease,
                cached.assigned_gateway_id,
            )
            binding = Binding.model_validate(challenge["binding"]).model_dump(
                mode="json"
            )
            require(
                all(binding[k] == v for k, v in scope.items())
                and binding["device_id"] == str(cached.device_id),
                "lease_scope",
            )
            profile = config.profiles.get(cached.catalog_id)
            require(
                profile is not None
                and all(binding[k] == v for k, v in profile.model_dump().items()),
                "workload_unapproved",
            )
            require(
                type(challenge["expires_at"]) is int
                and time.time() < challenge["expires_at"],
                "challenge_expired",
            )
            context = {
                "binding": binding,
                "config": config,
                "lock": asyncio.Lock(),
                "state": {"binding": binding, "batch_id": batch, "records": []},
            }
            guest = self.guest_factory(
                cached.client_address, config.guest_port, self.client_tls
            )
            await self.channel(guest, context)
            issued = int(time.time())
            statement = dict(
                kind="attestation-v1",
                issuer=config.issuer,
                binding=binding,
                nonce=challenge["nonce"],
                runtime_key=guest.runtime_key,
                issued_at=issued,
                expires_at=min(issued + 60, config.policy_expires_at),
                platform="sev-snp-cpu",
                chain_valid=True,
                tcb_current=True,
                revocation_checked=True,
                debug_disabled=True,
                workload_measured=True,
                protected_time=True,
                rollback_protected=True,
            )
            quote = await guest.post("/quote", statement)
            require(
                set(quote) == {"report", "runtime_key"}
                and quote["runtime_key"] == guest.runtime_key,
                "quote_scope",
            )
            submission = await self.attest(config, statement, quote["report"])
            session_proof, session = await self.owner(context, "register", submission)
            require(
                set(session)
                == {
                    "epoch",
                    "runtime_key",
                    "expires_at",
                    "binding",
                    "issuer_key",
                    "attestation_sha256",
                }
                and session["binding"] == binding
                and session["runtime_key"] == guest.runtime_key
                and session["issuer_key"] == config.issuer_key
                and session["attestation_sha256"] == digest(statement)
                and session["expires_at"] == statement["expires_at"]
                and time.time() < session["expires_at"],
                "session_scope",
            )
            uuid.UUID(session["epoch"])
            admission = dict(
                batch_id=batch,
                max_billable=2048 + work["max_tokens"],
                max_record_only=0,
                meters=sorted(cached.digest_meters),
            )
            state = context["state"]
            state.update(
                runtime_key=guest.runtime_key,
                attestation=submission,
                session_proof=session_proof,
                session=session,
                admission=admission,
                phase="admitting",
                owner_key=config.owner_key,
                guest_address=str(cached.client_address),
            )
            self.journal.save(batch, state)
            _, admitted = await self.owner(context, "admit", admission)
            expected = admission | {"epoch": session["epoch"]}
            require(
                all(admitted.get(k) == v for k, v in expected.items()),
                "admission_scope",
            )
            state["phase"] = "admitted"
            self.journal.save(batch, state)
            await self.channel(guest, context)
            recheck()
            require(
                not self.queue.fenced(tenant, lease)
                and time.time() < session["expires_at"],
                "execution_fenced",
            )
            self.active[(str(tenant), str(lease), batch)] = context
            state["phase"] = "executing"
            self.journal.save(batch, state)
            result = await guest.post(
                "/execute",
                work
                | dict(
                    batch_id=batch,
                    epoch=session["epoch"],
                    max_billable=admission["max_billable"],
                    max_record_only=0,
                    relay_url=config.relay_url,
                ),
            )
            require(
                set(result) == {"outcome", "output_hex"}
                and result["outcome"] == "completed",
                "execution_incomplete",
            )
            require(
                isinstance(result["output_hex"], str)
                and len(result["output_hex"]) <= 2 * 1024 * 1024,
                "output_oversized",
            )
            output = bytes.fromhex(result["output_hex"]).decode("utf-8")
            require(state.get("terminal") is not None, "unanchored_terminal")
            terminal = Checkpoint.model_validate(state["terminal"]["record"])
            require(terminal.outcome == "completed", "execution_incomplete")
            # Plane's recovery transaction owns exactly-once quantity forwarding.
            proof, recovered = await self.owner(context, "recover", {"batch_id": batch})
            require(
                recovered
                == dict(
                    batch_id=batch,
                    terminal_sha256=digest(terminal),
                    counters=terminal.counters.model_dump(),
                    billable=terminal.counters.billable,
                    policy_sha256=POLICY_DIGEST,
                ),
                "recovery_scope",
            )
            state.update(phase="recovered", recovery=proof)
            self.journal.save(batch, state)
            # A fresh channel may be needed after a long execution. Failure leaves
            # the committed recovery marker for #69; never discard local history.
            try:
                await self.channel(guest, context)
                retired = await guest.post(
                    "/retire",
                    dict(
                        batch_id=batch,
                        runtime_key=guest.runtime_key,
                        operation="recover",
                        proof=proof,
                    ),
                )
                require(retired == {"retired": True}, "retirement_reply")
                self.journal.retired(batch)
            except Exception:
                pass
            response = {
                "id": "chatcmpl-" + batch,
                "object": "chat.completion",
                "model": cached.catalog_id,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": output},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": terminal.counters.processed_input,
                    "completion_tokens": terminal.counters.accepted_output,
                    "total_tokens": terminal.counters.billable,
                },
            }
            return ProxiedChat(httpx.Response(200, json=response))
        finally:
            self.active.pop((str(tenant), str(lease), batch), None)
            self.leases.discard(identity)

    async def exchange(self, envelope):
        require(
            isinstance(envelope, dict)
            and set(envelope) == {"binding", "operation", "request"},
            "relay_envelope",
        )
        b = Binding.model_validate(envelope["binding"]).model_dump(mode="json")
        signed = Signed.model_validate(envelope["request"])
        operation = envelope["operation"]
        require(operation in {"start", "renew", "checkpoint"}, "relay_operation")
        raw_batch = signed.record.get("batch_id")
        context = self.active.get((b["tenant_id"], b["lease_id"], raw_batch))
        require(context is not None and context["binding"] == b, "relay_scope")
        async with context["lock"]:
            state = context["state"]
            cls = {
                "start": FreshStart,
                "renew": FreshRenewal,
                "checkpoint": Checkpoint,
            }[operation]
            record = verify(signed, cls, state["runtime_key"])
            require(
                record.binding.model_dump(mode="json") == b
                and str(record.epoch) == state["session"]["epoch"],
                "runtime_scope",
            )
            if operation != "start":
                require(
                    state.get("start") is not None
                    and str(record.start_id) == state["start"]["start_id"],
                    "start_scope",
                )
            if operation == "checkpoint":
                records = state["records"]
                if record.sequence <= len(records):
                    require(
                        records[record.sequence - 1] == envelope["request"],
                        "conflicting_checkpoint",
                    )
                else:
                    require(
                        not state.get("terminal")
                        and record.sequence == len(records) + 1,
                        "checkpoint_sequence",
                    )
                    previous = records[-1]["record"] if records else None
                    require(
                        record.previous_sha256
                        == (digest(previous) if previous else "0" * 64),
                        "checkpoint_chain",
                    )
                    values = record.counters.model_dump()
                    require(
                        previous is None
                        or all(values[k] >= previous["counters"][k] for k in values),
                        "counter_regression",
                    )
                    require(
                        record.counters.processed_input <= 2048
                        and record.counters.accepted_output
                        <= state["admission"]["max_billable"] - 2048
                        and record.counters.billable
                        <= state["admission"]["max_billable"]
                        and record.counters.cache_hits
                        + record.counters.rejected_speculative
                        == 0,
                        "counter_budget",
                    )
                    require(
                        record.outcome != "no_work" or not any(values.values()),
                        "invalid_no_work",
                    )
            proof, result = await self.owner(context, operation, envelope["request"])
            if operation == "start":
                require(
                    result["max_billable"] == state["admission"]["max_billable"]
                    and result["max_record_only"] == 0,
                    "start_budget",
                )
                uuid.UUID(result["start_id"])
                state["start"] = result
            elif operation == "checkpoint":
                require(
                    result == {"sha256": digest(record), "sequence": record.sequence},
                    "anchor_scope",
                )
                if record.sequence > len(state["records"]):
                    state["records"].append(envelope["request"])
                if record.outcome != "running":
                    state["terminal"] = envelope["request"]
            self.journal.save(raw_batch, state)
            return proof
