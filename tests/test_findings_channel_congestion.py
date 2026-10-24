"""WIFI-CHANNEL-CONGESTION: >= 6 redes en el mismo canal."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import channel_congestion

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _nets(channel: int, count: int) -> tuple[NetworkFact, ...]:
    return tuple(
        NetworkFact(
            bssid=f"aa:bb:cc:dd:ee:{i:02x}",
            ssid=f"Red {i}",
            channel=channel,
            rssi=-70,
            security="wpa2",
            first_seen=T0,
            last_seen=T0,
        )
        for i in range(count)
    )


def test_congestion_fires_at_umbral() -> None:
    hits = channel_congestion.evaluate(RuleContext(session_id="s", networks=_nets(6, 6)))
    assert len(hits) == 1
    assert hits[0].severidad == "baja"
    assert hits[0].activo == {"canal": "6"}
    assert len(hits[0].evidencia["redes"]) == 6


def test_congestion_negative_below_umbral() -> None:
    assert channel_congestion.evaluate(RuleContext(session_id="s", networks=_nets(6, 5))) == []
    # Redes sin canal conocido no cuentan.
    sin_canal = tuple(
        NetworkFact(
            bssid=f"aa:bb:cc:dd:ee:{i:02x}",
            ssid=f"Red {i}",
            channel=None,
            rssi=-70,
            security="wpa2",
        )
        for i in range(8)
    )
    assert channel_congestion.evaluate(RuleContext(session_id="s", networks=sin_canal)) == []
