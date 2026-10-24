"""WIFI-WEP: red con WEP. Caso positivo y negativo."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import wep

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str, security: str | None) -> NetworkFact:
    return NetworkFact(
        bssid=bssid, ssid=ssid, channel=3, rssi=-70, security=security, first_seen=T0, last_seen=T0
    )


def test_wep_fires() -> None:
    hits = wep.evaluate(
        RuleContext(session_id="s", networks=(_net("11:22:33:44:55:02", "Legacy", "wep"),))
    )
    assert len(hits) == 1
    assert hits[0].severidad == "alta"
    assert "WEP" in hits[0].titulo


def test_wep_negative() -> None:
    ctx = RuleContext(
        session_id="s",
        networks=(
            _net("11:22:33:44:55:03", "WPA2", "wpa2"),
            _net("11:22:33:44:55:04", "Abierta", "open"),
        ),
    )
    assert wep.evaluate(ctx) == []
