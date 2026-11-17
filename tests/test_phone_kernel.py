import base64

import pytest

from hypermesh_gateway_service import phone_kernel as kernel
from hypermesh_gateway_service.phone_mesh import PhoneUnavailable


def test_phone_firewall_is_separate_and_restricts_both_directions():
    driver = kernel.KernelPhoneDriver("10.77.1.9", 9443)
    rules = driver.rules()
    assert "wg-hm" not in rules
    assert 'iifname "wg-phone" drop' in rules
    assert 'oifname "wg-phone" drop' in rules
    assert "ip saddr @clients ip daddr 10.77.1.9 tcp dport 9443 accept" in rules
    assert "ip daddr @clients ip saddr 10.77.1.9 tcp sport 9443 ct state established accept" in rules
    assert "flags timeout" in rules
    assert "update @clients" not in rules


async def test_kernel_timeout_subtracts_command_budget(monkeypatch):
    calls = []
    driver = kernel.KernelPhoneDriver("10.77.1.9", 9443,
                                     command=lambda args, **kw: calls.append((args, kw)))
    driver.ready = True
    monkeypatch.setattr(kernel.time, "time", lambda: 1000.5)
    key = base64.b64encode(b"x" * 32).decode()
    await driver.apply(key, "10.90.0.2", 1060)
    assert "timeout 54s" in calls[-1][1]["script"]
    assert calls[0][0] == ["wg", "set", "wg-phone", "peer", key, "allowed-ips", "10.90.0.2/32"]
    await driver.remove(key, "10.90.0.2")
    assert calls[-2][1]["script"] == "flush set inet hm_phone clients\n"
    assert calls[-1][0][-1] == "remove"


async def test_unavailable_or_expired_never_opens_firewall(monkeypatch):
    calls = []
    driver = kernel.KernelPhoneDriver("10.77.1.9", 9443,
                                     command=lambda args, **kw: calls.append((args, kw)))
    with pytest.raises(PhoneUnavailable): await driver.apply("key", "10.90.0.2", 1060)
    assert not calls
    driver.ready = True
    monkeypatch.setattr(kernel.time, "time", lambda: 1056)
    with pytest.raises(PhoneUnavailable): await driver.apply("key", "10.90.0.2", 1060)
    assert all(c[0][0] != "nft" for c in calls)


async def test_refresh_does_not_extend_other_peer_after_clock_moves_backward(monkeypatch):
    scripts = []
    clock = [1000, 2000]
    monkeypatch.setattr(kernel.time, "time", lambda: clock[0])
    monkeypatch.setattr(kernel.time, "monotonic", lambda: clock[1])
    driver = kernel.KernelPhoneDriver("10.77.1.9", 9443,
        command=lambda args, **kw: scripts.append(kw.get("script", "")))
    driver.ready = True
    await driver.apply("first-key", "10.90.0.2", 1060)
    clock[:] = [990, 2030]
    await driver.apply("second-key", "10.90.0.3", 1050)
    assert "10.90.0.2 timeout 25s" in scripts[-1]
    assert "10.90.0.3 timeout 55s" in scripts[-1]
    assert "destroy" not in driver.rules()
