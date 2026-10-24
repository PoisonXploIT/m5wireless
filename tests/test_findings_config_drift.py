"""WIFI-CONFIG-DRIFT: mismo BSSID, seguridad o canal distintos entre sesiones."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import config_drift

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 25, 9, 0, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str, security: str | None, channel: int, when: datetime) -> NetworkFact:
    return NetworkFact(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi=-60,
        security=security,
        first_seen=when,
        last_seen=when,
    )


def test_drift_fires_when_security_downgrades() -> None:
    ctx = RuleContext(
        session_id="s2",
        networks=(_net("11:22:33:44:55:01", "Oficina-A", "open", 6, T1),),
        previous_networks=(_net("11:22:33:44:55:01", "Oficina-A", "wpa2", 6, T0),),
    )
    hits = config_drift.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].severidad == "media"
    assert hits[0].evidencia["cambios"]["seguridad"] == {"antes": "wpa2", "ahora": "open"}
    assert "canal" not in hits[0].evidencia["cambios"]


def test_drift_fires_on_channel_change() -> None:
    ctx = RuleContext(
        session_id="s2",
        networks=(_net("11:22:33:44:55:01", "Oficina-A", "wpa2", 1, T1),),
        previous_networks=(_net("11:22:33:44:55:01", "Oficina-A", "wpa2", 6, T0),),
    )
    hits = config_drift.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].evidencia["cambios"]["canal"] == {"antes": 6, "ahora": 1}


def test_drift_negative_no_change_and_no_history() -> None:
    ctx = RuleContext(
        session_id="s2",
        networks=(_net("11:22:33:44:55:01", "Oficina-A", "wpa2", 6, T1),),
        previous_networks=(_net("11:22:33:44:55:01", "Oficina-A", "wpa2", 6, T0),),
    )
    assert config_drift.evaluate(ctx) == []
    # Sin sesiones anteriores no se puede afirmar nada.
    assert config_drift.evaluate(RuleContext(session_id="s1", networks=ctx.networks)) == []
