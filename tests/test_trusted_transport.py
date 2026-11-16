"""TLS pin-before-body and bounded HTTP parser unit contracts; no sockets."""

import asyncio
import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from hypermesh_gateway_service.trusted_meter import transport
from hypermesh_gateway_service.trusted_meter.wire import Refusal


def certificate(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2000, 1, 1))
        .not_valid_after(datetime.datetime(2001, 1, 1))
        .sign(key, None)
        .public_bytes(Encoding.DER)
    )


async def test_tls_key_change_is_rejected_before_prompt_bytes(monkeypatch):
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    writers = []

    async def connect(*args, **kwargs):
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        reader.feed_eof()
        writer = SimpleNamespace(
            sent=bytearray(),
            drain=AsyncMock(),
            close=lambda: None,
            wait_closed=AsyncMock(),
        )
        writer.write = writer.sent.extend
        active = key if not writers else other
        writer.get_extra_info = lambda _: SimpleNamespace(
            version=lambda: "TLSv1.3", getpeercert=lambda **kw: certificate(active)
        )
        writers.append(writer)
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", connect)
    guest = transport.Guest("192.0.2.1/32", 8080, None)
    await guest.post("/channels/challenge", {})
    assert guest.runtime_key == key.public_key().public_bytes_raw().hex()
    with pytest.raises(Refusal, match="runtime_key_changed"):
        await guest.post("/execute", {"messages": "private prompt"})
    assert not writers[1].sent


@pytest.mark.parametrize(
    "fields,raw",
    [
        ({"content-length": "100"}, b"{}"),
        ({"content-length": "-1"}, b""),
        ({"transfer-encoding": "chunked", "content-length": "2"}, b"{}"),
        ({"transfer-encoding": "chunked"}, b"ffffff\r\n"),
        ({"transfer-encoding": "gzip"}, b"{}"),
    ],
)
async def test_invalid_or_oversized_framing_refuses(fields, raw):
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    with pytest.raises((ValueError, asyncio.IncompleteReadError)):
        await transport.body(reader, fields, 16)


async def test_chunked_and_duplicate_json_contract():
    reader = asyncio.StreamReader()
    reader.feed_data(b"1\r\n{\r\n1\r\n}\r\n0\r\n\r\n")
    reader.feed_eof()
    assert (
        transport.decode(
            await transport.body(reader, {"transfer-encoding": "chunked"}, 16)
        )
        == {}
    )
    with pytest.raises(Refusal, match="duplicate"):
        transport.decode(b'{"count":1,"count":2}')
    with pytest.raises(Refusal):
        transport.decode(b'{"count":NaN}')


@pytest.mark.parametrize(
    "address", ["https://provider.example", "provider.example", "127.0.0.1/invalid"]
)
def test_guest_destination_requires_assigned_literal_address(address):
    with pytest.raises(ValueError):
        transport.Guest(address, 8080, None)
