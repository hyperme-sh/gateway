"""Locally approved verifier and independent workload issuer; no host trust roots."""

import asyncio
import hashlib
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from pydantic import Field, model_validator
from .wire import Wire, Digest, Attestation, Signed, Refusal, canonical, verify
from .transport import decode


class Binary(Wire):
    executable: str = Field(min_length=1, max_length=4096)
    sha256: Digest


class Profile(Wire):
    model_sha256: Digest
    tokenizer_sha256: Digest
    template_sha256: Digest
    runtime_sha256: Digest
    measurement: str = Field(pattern=r"^[0-9a-f]{96}$")


class Policy(Wire):
    owner_key: Digest
    issuer: str = Field(min_length=1, max_length=128)
    issuer_key: Digest
    issuer_command: Binary
    verifier: Binary
    profiles: dict[str, Profile] = Field(max_length=1024)
    product: str = Field(pattern=r"^(Milan|Genoa|Turin)$")
    minimum_tcb: int = Field(strict=True, gt=0, lt=2**64)
    minimum_launch_tcb: int = Field(strict=True, gt=0, lt=2**64)
    policy_expires_at: int = Field(strict=True, gt=0)
    revoked_runtime_keys: list[Digest] = Field(default_factory=list, max_length=1024)
    relay_bind: str
    relay_port: int = Field(strict=True, ge=1024, le=65535)
    relay_url: str
    guest_port: int = Field(strict=True, ge=1, le=65535, default=8080)

    @model_validator(mode="after")
    def endpoint(self):
        url = urlsplit(self.relay_url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.path != "/trusted-meter/relay"
            or url.query
            or url.fragment
            or url.port != self.relay_port
        ):
            raise ValueError("Dedicated HTTPS relay endpoint required")
        return self


def configured_history():
    path = os.environ.get("HYPERMESH_TRUSTED_METER_CONFIG")
    if not path:
        raise Refusal("trusted_meter_unconfigured")
    with open(path, "rb") as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise Refusal("policy_oversized")
    policy = Policy.model_validate(decode(raw))
    return policy


def configured():
    policy = configured_history()
    if time.time() >= policy.policy_expires_at:
        raise Refusal("vendor_policy_expired")
    return policy


async def command(binary, args, raw, *, output=False):
    path = Path(binary.executable)
    if (
        not path.is_absolute()
        or hashlib.sha256(path.read_bytes()).hexdigest() != binary.sha256
    ):
        raise Refusal("approved_binary_changed")
    process = await asyncio.create_subprocess_exec(
        str(path),
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE if output else asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        limit=16384,
    )
    try:
        async with asyncio.timeout(15):
            process.stdin.write(raw)
            await process.stdin.drain()
            process.stdin.close()
            result = bytearray()
            if output:
                while chunk := await process.stdout.read(4096):
                    result.extend(chunk)
                    if len(result) > 16384:
                        raise Refusal("issuer_reply_oversized")
            await process.wait()
            if process.returncode != 0:
                raise Refusal("vendor_or_issuer_refused")
            return bytes(result)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def attest(policy, statement, report):
    record = Attestation.model_validate(statement)
    if not isinstance(report, str) or len(report) != 2368:
        raise Refusal("invalid_vendor_report")
    raw = bytes.fromhex(report)
    if len(raw) != 1184 or record.expires_at > policy.policy_expires_at:
        raise Refusal("invalid_vendor_policy")
    args = [
        "-in=-",
        "-inform=bin",
        "-quiet",
        "-product=" + policy.product,
        "-check_crl=true",
        "-network=true",
        "-timeout=5s",
        "-max_retry_delay=1s",
        "-guest_policy=131072",
        "-provisional=false",
        "-vmpl=0",
        "-minimum_tcb=" + str(policy.minimum_tcb),
        "-minimum_launch_tcb=" + str(policy.minimum_launch_tcb),
        "-measurement=" + record.binding.measurement,
        "-report_data="
        + hashlib.sha512(b"hypermesh-snp-meter-v1\x00" + canonical(record)).hexdigest(),
    ]
    await command(policy.verifier, args, raw)
    # The independently operated issuer must validate chip/host assignment and
    # protected-time/workload policy itself. Gateway does not hold its private key.
    signed = Signed.model_validate(
        decode(
            await command(
                policy.issuer_command,
                [],
                canonical({"record": statement, "snp_report": report}),
                output=True,
            )
        )
    )
    checked = verify(signed, Attestation, policy.issuer_key)
    if checked != record or checked.issuer != policy.issuer:
        raise Refusal("issuer_scope")
    return signed.model_dump(mode="json") | {"snp_report": report}
