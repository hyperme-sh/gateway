"""Strict count-only wire records and the owner-selected billing policy."""

import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

MAX = 2**63 - 1
Count = Annotated[int, Field(strict=True, ge=0, le=MAX)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
POLICY = "processed-input-accepted-output-v1"
POLICY_DIGEST = hashlib.sha256(POLICY.encode()).hexdigest()
DOMAIN = b"hypermesh-trusted-meter-v1\x00"


class Refusal(ValueError):
    pass


class Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Binding(Wire):
    tenant_id: UUID
    lease_id: UUID
    device_id: UUID
    gateway_id: UUID
    model_sha256: Digest
    tokenizer_sha256: Digest
    template_sha256: Digest
    runtime_sha256: Digest
    measurement: Annotated[str, Field(pattern=r"^[0-9a-f]{96}$")]
    policy_sha256: Literal[POLICY_DIGEST] = POLICY_DIGEST


class Counters(Wire):
    processed_input: Count
    accepted_output: Count
    hidden_output: Count
    cache_hits: Count
    rejected_speculative: Count

    @model_validator(mode="after")
    def bounded(self):
        if self.hidden_output > self.accepted_output:
            raise ValueError("Hidden output is a subset of accepted output")
        if self.processed_input + self.accepted_output > MAX:
            raise ValueError("Billable total exceeds storage range")
        return self

    @property
    def billable(self):
        return self.processed_input + self.accepted_output


class Channel(Wire):
    nonce: Digest
    runtime_key: Digest
    gateway_key: Digest


class Attestation(Wire):
    kind: Literal["attestation-v1"]
    issuer: str = Field(min_length=1, max_length=128)
    binding: Binding
    nonce: Digest
    runtime_key: Digest
    issued_at: Count
    expires_at: Count
    platform: Literal["sev-snp-cpu"]
    chain_valid: Literal[True]
    tcb_current: Literal[True]
    revocation_checked: Literal[True]
    debug_disabled: Literal[True]
    workload_measured: Literal[True]
    protected_time: Literal[True]
    rollback_protected: Literal[True]


class Start(Wire):
    kind: Literal["start-v1"]
    binding: Binding
    epoch: UUID
    batch_id: UUID


class FreshStart(Start):
    kind: Literal["start-v2"]
    nonce: Digest


class Renewal(Start):
    kind: Literal["renew-v1"]
    start_id: UUID
    sequence: Annotated[int, Field(strict=True, ge=1, le=256)]


class FreshRenewal(Renewal):
    kind: Literal["renew-v2"]
    nonce: Digest


class Checkpoint(Wire):
    kind: Literal["checkpoint-v1"]
    binding: Binding
    epoch: UUID
    batch_id: UUID
    start_id: UUID
    sequence: Annotated[int, Field(strict=True, ge=1, le=256)]
    previous_sha256: Digest
    counters: Counters
    outcome: Literal["running", "completed", "interrupted", "no_work"]


class Signed(Wire):
    record: dict

    @model_validator(mode="after")
    def bounded_record(self):
        if len(canonical(self.record)) > 8192:
            raise ValueError("Signed record exceeds limit")
        return self

    signature: str = Field(pattern=r"^[0-9a-f]{128}$")


def canonical(record):
    value = record.model_dump(mode="json") if isinstance(record, BaseModel) else record
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(record):
    return hashlib.sha256(canonical(record)).hexdigest()


def verify(signed, record_type, key):
    record = record_type.model_validate(signed.record)
    # Signing normalization must never hide omitted/default or coerced fields.
    if canonical(record) != canonical(signed.record):
        raise Refusal("noncanonical_record")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(signed.signature), DOMAIN + canonical(record)
        )
    except (ValueError, InvalidSignature):
        raise Refusal("invalid_signature") from None
    return record
