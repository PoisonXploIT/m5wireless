"""WIFI-EVILTWIN: mismo SSID, distinto BSSID, seguridad o canal distinto."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import evil_twin

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 24, 9, 12, 0, tzinfo=UTC)


def _net(
    bssid: str, ssid: str | None, security: str | None, channel: int, seen: datetime
) -> NetworkFact:
    return NetworkFact(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi=-60,
        security=security,
        first_seen=seen,
        last_seen=seen,
    )


def test_evil_twin_fires_and_blames_the_weaker_later_bssid() -> None:
    ctx = RuleContext(
        session_id="s",
        networks=(
            _net("11:22:33:44:55:01", "Oficina-A", "wpa2", 6, T0),
            _net("aa:bb:cc:dd:ee:01", "Oficina-A", "open", 1, T1),
        ),
    )
    hits = evil_twin.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].severidad == "alta"
    assert hits[0].activo == {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "Oficina-A"}
    assert hits[0].evidencia["referencia"] == "11:22:33:44:55:01"
    assert len(hits[0].evidencia["bssids"]) == 2


def test_evil_twin_negative_same_ssid_same_channel_and_security() -> None:
    """Dos APs del mismo SSID, misma seguridad y mismo canal: no se dispara."""
    ctx = RuleContext(
        session_id="s",
        networks=(
            _net("11:22:33:44:55:01", "Oficina-A", "wpa2", 6, T0),
            _net("11:22:33:44:55:02", "Oficina-A", "wpa2", 6, T1),
        ),
    )
    assert evil_twin.evaluate(ctx) == []


def test_evil_twin_negative_single_network() -> None:
    assert (
        evil_twin.evaluate(
            RuleContext(session_id="s", networks=(_net("11:22:33:44:55:01", "A", "wpa2", 6, T0),))
        )
        == []
    )
