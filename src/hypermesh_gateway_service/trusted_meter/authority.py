"""Verify each owner reply against the exact operation, request and scope."""

from typing import Literal
from uuid import UUID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .wire import Wire, Digest, Refusal, canonical, digest


class OwnerRecord(Wire):
    kind: Literal["owner-meter-v1"]
    operation: str
    tenant_id: UUID
    lease_id: UUID
    gateway_id: UUID
    request_sha256: Digest
    result: dict


def owner_reply(raw, key, operation, payload, tenant, lease, gateway):
    # Archive readback may exceed the bounded execution-record envelope.
    if not isinstance(raw, dict) or set(raw) != {"record", "signature"}:
        raise Refusal("owner_envelope")
    record = OwnerRecord.model_validate(raw["record"])
    if canonical(record) != canonical(raw["record"]):
        raise Refusal("owner_noncanonical")
    if (
        record.operation != operation
        or record.tenant_id != UUID(str(tenant))
        or record.lease_id != UUID(str(lease))
        or record.gateway_id != UUID(str(gateway))
        or record.request_sha256 != digest(payload)
    ):
        raise Refusal("owner_scope")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(raw["signature"]),
            b"hypermesh-meter-owner-v1\x00" + canonical(record),
        )
    except Exception:
        raise Refusal("owner_signature") from None
    return record.result


PATHS = {
    "challenge": "challenge",
    "channel": "channels",
    "register": "sessions",
    "admit": "admissions",
    "start": "starts",
    "renew": "renewals",
    "checkpoint": "checkpoints",
    "recover": "recover",
    "cancel": "cancel",
    "archive-dispute": "archives/disputes",
    "archive-read": "archives/read",
}
