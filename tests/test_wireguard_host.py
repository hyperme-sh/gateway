import base64
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import uuid

import pytest

from hypermesh_gateway_service import wg, wg_identity, wireguard_host
from hypermesh_gateway_service.control_plane import GatewayTunnel
from hypermesh_gateway_service.routes import apply_allocated_tunnels


PUBLIC = base64.b64encode(bytes(range(32))).decode()
PEER = base64.b64encode(bytes(range(1, 33))).decode()
OTHER = base64.b64encode(bytes(range(2, 34))).decode()


def test_host_mode_never_opens_a_private_identity_file(monkeypatch):
    monkeypatch.setenv(wireguard_host.SOCKET_ENV, "/run/gateway/wireguard.sock")
    monkeypatch.setenv("HYPERMESH_WG_EXPECTED_PUBLIC_KEY", PUBLIC)
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "1")
    monkeypatch.setattr(wireguard_host, "request", Mock(return_value={"ok": True, "public_key": PUBLIC}))
    monkeypatch.setattr(wg_identity, "read_private_key", Mock(side_effect=AssertionError("private key read")))
    assert wg_identity.local_identity([], registration_supported=True) == (None, PUBLIC)
    row = {"status": "allocated", "server_public_key": OTHER}
    with pytest.raises(ValueError, match="differs from assigned peers"):
        wg_identity.local_identity([row], registration_supported=True)
    with pytest.raises(ValueError, match="public-only Plane"):
        wg_identity.local_identity([], registration_supported=False)
    assert not Path(os.environ["HYPERMESH_WG_PRIVATE_KEY_FILE"]).exists()
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    with pytest.raises(ValueError, match="requires peer enforcement"):
        wg_identity.retained_identity()


def test_host_mode_enforces_peer_health_even_without_tun(monkeypatch):
    monkeypatch.setenv(wireguard_host.SOCKET_ENV, "/run/gateway/wireguard.sock")
    monkeypatch.setattr(wg, "tun_available", lambda: False)
    stats = Mock(return_value=(0, 1, 2))
    monkeypatch.setattr(wireguard_host, "peer_stats", stats)
    assert not wg.peer_is_up(PEER, now=1000)
    stats.return_value = (995, 3, 4)
    assert wg.peer_is_up(PEER, now=1000)
    assert not wg.peer_is_up(PEER, now=2000)
    assert wg.peer_counters(PEER) == (3, 4, 1)
    stats.side_effect = RuntimeError("offline")
    assert not wg.peer_is_up(PEER, now=1000)


def test_host_mode_applies_only_its_public_assignments_without_key_material(monkeypatch):
    monkeypatch.setenv(wireguard_host.SOCKET_ENV, "/run/gateway/wireguard.sock")
    monkeypatch.setenv("HYPERMESH_WG_EXPECTED_PUBLIC_KEY", PUBLIC)
    request = Mock(return_value={"ok": True})
    monkeypatch.setattr(wireguard_host, "request", request)
    common = dict(lease_id=None, status="allocated", endpoint="", server_private_key=None,
                  allowed_ips="10.77.0.2/32", client_address="10.77.0.2/32")
    own = GatewayTunnel(tunnel_id=uuid.uuid4(), server_public_key=PUBLIC, peer_public_key=PEER, **common)
    foreign = GatewayTunnel(tunnel_id=uuid.uuid4(), server_public_key=OTHER, peer_public_key=OTHER, **common)
    assert apply_allocated_tunnels([own, foreign]) == 1
    request.assert_called_once_with("apply", peer=PEER, address="10.77.0.2")


def test_wireguard_host_refuses_outside_and_occupied_routes():
    commands = []

    def run(arguments, **kwargs):
        commands.append(arguments)
        output = {
            "public-key": PUBLIC,
            "allowed-ips": f"{OTHER}\t10.77.0.3/32, 10.77.0.4/32\n",
            "latest-handshakes": f"{PEER}\t120\n",
            "transfer": f"{PEER}\t340\t560\n",
        }.get(arguments[-1], "")
        return SimpleNamespace(stdout=output)

    service = wireguard_host.Interface("wg0", "10.77.0.0/24", PUBLIC, run=run)
    for address in ("10.77.1.2", "10.77.0.1", "10.77.0.3"):
        with pytest.raises(ValueError):
            service.handle({"operation": "apply", "peer": PEER, "address": address})
    assert all(command[1] == "show" for command in commands)
    assert service.handle({"operation": "apply", "peer": PEER, "address": "10.77.0.2"}) == {"ok": True}
    assert commands[-1] == ["/usr/bin/wg", "set", "wg0", "peer", PEER, "allowed-ips", "10.77.0.2/32"]
    assert service.handle({"operation": "stats", "peer": PEER}) == {"ok": True, "handshake": 120, "rx": 340, "tx": 560}
    with pytest.raises(ValueError, match="Unsupported"):
        service.handle({"operation": "private-key"})
    assert not any("dump" in command or "private-key" in command for command in commands)


def test_message_reader_caps_input_and_preserves_only_one_request():
    connection = Mock()
    connection.gettimeout.return_value = 2
    connection.recv.side_effect = [b'{"operation":', b'"identity"}\n']
    assert wireguard_host.read_message(connection) == {"operation": "identity"}
    connection.recv.side_effect = [b"x" * (wireguard_host.MAX_MESSAGE + 1)]
    with pytest.raises(ValueError, match="Invalid WireGuard host message"):
        wireguard_host.read_message(connection)
