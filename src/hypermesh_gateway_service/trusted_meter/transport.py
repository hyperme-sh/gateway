"""TLS 1.3 with explicit attested-key checks before sending sensitive bodies."""

import asyncio
import datetime
import ipaddress
import json
import ssl
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from .wire import Refusal

LIMIT = 4 * 1024 * 1024


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal("duplicate_json_field")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refusal("invalid_number")),
    )


def contexts():
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "trusted-meter")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, None)
    )
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = (
        ssl.CERT_NONE
    )  # Every connection is pinned below before its body is sent.
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    for context in (client, server):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    with tempfile.TemporaryDirectory(prefix="meter-tls-") as directory:
        private, public = Path(directory) / "key.pem", Path(directory) / "cert.pem"
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private.chmod(0o600)
        public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        for context in (client, server):
            context.load_cert_chain(public, private)
    return key.public_key().public_bytes_raw().hex(), client, server


async def headers(reader):
    raw = await reader.readuntil(b"\r\n\r\n")
    if len(raw) > 16384:
        raise Refusal("headers_oversized")
    lines = raw.decode("ascii").split("\r\n")
    result = {}
    for line in lines[1:]:
        if not line:
            continue
        key, value = line.split(":", 1)
        key = key.lower()
        if key in result:
            raise Refusal("duplicate_header")
        result[key] = value.strip()
    return lines[0], result


async def body(reader, fields, limit):
    if "transfer-encoding" in fields:
        if (
            fields["transfer-encoding"].lower() != "chunked"
            or "content-length" in fields
        ):
            raise Refusal("invalid_framing")
        result = bytearray()
        while True:
            line = await reader.readuntil(b"\r\n")
            if len(line) > 32:
                raise Refusal("invalid_chunk")
            length = int(line.strip(), 16)
            if length < 0 or length + len(result) > limit:
                raise Refusal("body_oversized")
            if length == 0:
                if await reader.readexactly(2) != b"\r\n":
                    raise Refusal("trailers_unsupported")
                return bytes(result)
            result += await reader.readexactly(length)
            if await reader.readexactly(2) != b"\r\n":
                raise Refusal("invalid_chunk")
    length = int(fields["content-length"])
    if not 0 <= length <= limit:
        raise Refusal("body_oversized")
    return await reader.readexactly(length)


class Guest:
    def __init__(self, address, port, context):
        self.address = str(ipaddress.ip_interface(address).ip)
        self.port, self.context = port, context
        self.runtime_key = None
        self.channel = None

    async def post(self, path, payload):
        raw = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode()
        if len(raw) > 65536:
            raise Refusal("request_oversized")
        async with asyncio.timeout(90 if path == "/execute" else 15):
            reader, writer = await asyncio.open_connection(
                self.address,
                self.port,
                ssl=self.context,
                server_hostname="",
                limit=16384,
            )
            try:
                tls = writer.get_extra_info("ssl_object")
                if tls.version() != "TLSv1.3":
                    raise Refusal("tls_version")
                key = x509.load_der_x509_certificate(
                    tls.getpeercert(binary_form=True)
                ).public_key()
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )

                if not isinstance(key, Ed25519PublicKey):
                    raise Refusal("runtime_key_type")
                public = key.public_bytes_raw().hex()
                if self.runtime_key is None:
                    if path not in {"/channels/challenge", "/history/channels/challenge"}:
                        raise Refusal("channel_uninitialized")
                    self.runtime_key = public
                if public != self.runtime_key:
                    raise Refusal("runtime_key_changed")
                token = (
                    f"X-Hypermesh-Meter-Channel: {self.channel}\r\n"
                    if self.channel
                    else ""
                )
                writer.write(
                    (
                        f"POST {path} HTTP/1.1\r\nHost: meter\r\nConnection: close\r\nContent-Type: application/json\r\n{token}Content-Length: {len(raw)}\r\n\r\n"
                    ).encode()
                    + raw
                )
                await writer.drain()
                status, fields = await headers(reader)
                if status.split(" ")[1] != "200":
                    raise Refusal("guest_refused")
                return decode(await body(reader, fields, LIMIT))
            finally:
                writer.close()
                await writer.wait_closed()


class Relay:
    def __init__(self, config, context, exchange):
        self.config, self.context, self.exchange = config, context, exchange
        self.server = None
        self.tasks = set()

    async def start(self):
        self.server = await asyncio.start_server(
            self.accept,
            self.config.relay_bind,
            self.config.relay_port,
            ssl=self.context,
            ssl_handshake_timeout=5,
            limit=16384,
        )

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        if len(self.tasks) >= 64:
            writer.close()
            return
        self.tasks.add(task)
        try:
            async with asyncio.timeout(15):
                status, fields = await headers(reader)
                if status != "POST /trusted-meter/relay HTTP/1.1":
                    raise Refusal("relay_route")
                result = await self.exchange(decode(await body(reader, fields, 16384)))
                raw = json.dumps(result, separators=(",", ":")).encode()
                writer.write(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode()
                    + raw
                )
                await writer.drain()
        except Exception:
            writer.write(
                b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        finally:
            self.tasks.discard(task)
            writer.close()
            await writer.wait_closed()

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
