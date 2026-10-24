"""WIFI-OPEN: red abierta. Caso positivo y negativo."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import open_network

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str, security: str | None) -> NetworkFact:
    return NetworkFact(
        bssid=bssid, ssid=ssid, channel=6, rssi=-60, security=security, first_seen=T0, last_seen=T0
    )


def test_open_fires() -> None:
    ctx = RuleContext(session_id="s", networks=(_net("aa:bb:cc:dd:ee:01", "Abierta", "open"),))
    hits = open_network.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].rule_id == "WIFI-OPEN"
    assert hits[0].severidad == "alta"
    assert hits[0].activo == {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "Abierta"}
    assert "WPA2" in hits[0].recomendacion


def test_open_negative_wpa2_and_unknown_security() -> None:
    ctx = RuleContext(
        session_id="s",
        networks=(
            _net("aa:bb:cc:dd:ee:02", "WPA2", "wpa2"),
            _net("aa:bb:cc:dd:ee:03", "Sin dato", None),
        ),
    )
    assert open_network.evaluate(ctx) == []
