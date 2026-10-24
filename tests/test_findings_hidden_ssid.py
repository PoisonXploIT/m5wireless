"""WIFI-HIDDEN: SSID vacio con BSSID visible. Caso positivo y negativo."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import hidden_ssid

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str | None) -> NetworkFact:
    return NetworkFact(
        bssid=bssid, ssid=ssid, channel=6, rssi=-60, security="wpa2", first_seen=T0, last_seen=T0
    )


def test_hidden_fires_with_none_and_with_empty_ssid() -> None:
    ctx = RuleContext(
        session_id="s", networks=(_net("aa:bb:cc:dd:ee:20", None), _net("aa:bb:cc:dd:ee:21", ""))
    )
    hits = hidden_ssid.evaluate(ctx)
    assert len(hits) == 2
    assert hits[0].severidad == "info"
    assert hits[0].activo == {"bssid": "aa:bb:cc:dd:ee:20"}


def test_hidden_negative_named_networks() -> None:
    assert (
        hidden_ssid.evaluate(
            RuleContext(session_id="s", networks=(_net("aa:bb:cc:dd:ee:22", "Con nombre"),))
        )
        == []
    )
