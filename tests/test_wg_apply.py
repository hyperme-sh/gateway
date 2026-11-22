"""Gateway WireGuard apply stays additive when wg-hm already exists."""

from __future__ import annotations

import subprocess

from hypermesh_gateway_service import wg


def _clear() -> None:
    wg._applied_host_peers.clear()


def test_standing_iface_still_receives_the_host_peer(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake(cmd: list[str]) -> None:
        calls.append(cmd)
        if cmd[:3] == ["ip", "link", "add"]:
            raise subprocess.CalledProcessError(2, cmd)
        if cmd[:3] == ["ip", "address", "add"]:
            raise subprocess.CalledProcessError(2, cmd)

    monkeypatch.setattr(wg, "_run", fake)
    monkeypatch.setattr(wg, "should_apply", lambda: True)
    _clear()

    wg.apply_gateway(
        server_private_key="priv",
        peer_public_key="pub-a",
        client_address="10.77.0.2/32",
    )

    assert [
        "wg",
        "set",
        wg.WG_IFACE,
        "peer",
        "pub-a",
        "allowed-ips",
        "10.77.0.2/32",
    ] in calls
    assert "pub-a" in wg._applied_host_peers


def test_second_host_peer_applies_on_an_existing_iface(monkeypatch) -> None:
    calls: list[list[str]] = []
    adds = {"n": 0}

    def fake(cmd: list[str]) -> None:
        calls.append(cmd)
        if cmd[:3] == ["ip", "link", "add"]:
            adds["n"] += 1
            if adds["n"] > 1:
                raise subprocess.CalledProcessError(2, cmd)
        if cmd[:3] == ["ip", "address", "add"] and adds["n"] > 1:
            raise subprocess.CalledProcessError(2, cmd)

    monkeypatch.setattr(wg, "_run", fake)
    monkeypatch.setattr(wg, "should_apply", lambda: True)
    _clear()

    wg.apply_gateway(
        server_private_key="priv",
        peer_public_key="pub-a",
        client_address="10.77.0.2/32",
    )
    wg.apply_gateway(
        server_private_key="priv",
        peer_public_key="pub-b",
        client_address="10.77.0.3/32",
    )

    assert ["wg", "set", wg.WG_IFACE, "peer", "pub-b", "allowed-ips", "10.77.0.3/32"] in calls
    assert wg._applied_host_peers == {"pub-a", "pub-b"}

def test_skipped_or_failed_apply_is_not_reported_as_applied(monkeypatch) -> None:
    args = dict(server_private_key="priv", peer_public_key="unapplied", client_address="10.77.0.2/32")
    monkeypatch.setattr(wg, "should_apply", lambda: False)
    assert wg.apply_gateway(**args) is False

    def fail(cmd):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(wg, "should_apply", lambda: True)
    monkeypatch.setattr(wg, "_run", fail)
    assert wg.apply_gateway(**args) is False
    assert "unapplied" not in wg._applied_host_peers


def test_cached_peer_is_reapplied_when_kernel_route_is_missing_or_changed(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(wg, "_run", calls.append)
    monkeypatch.setattr(wg, "should_apply", lambda: True)
    _clear()
    args = dict(server_private_key="priv", peer_public_key="pub-a", client_address="10.77.0.2/32")
    assert wg.apply_gateway(**args)

    for routes, should_reapply in (
        ("pub-a\t10.77.0.2/32\n", False),
        ("pub-a\t10.77.0.9/32\n", True),
        ("other\t10.77.0.2/32\n", True),
    ):
        calls.clear()

        def read_allowed_ips(cmd, **kwargs):
            assert cmd == ["wg", "show", wg.WG_IFACE, "allowed-ips"]
            return subprocess.CompletedProcess(cmd, 0, routes)

        monkeypatch.setattr(wg.subprocess, "run", read_allowed_ips)
        assert wg.apply_gateway(**args)
        set_peer = ["wg", "set", wg.WG_IFACE, "peer", "pub-a", "allowed-ips", "10.77.0.2/32"]
        assert (set_peer in calls) is should_reapply
