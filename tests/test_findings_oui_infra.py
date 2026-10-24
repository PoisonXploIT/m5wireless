"""WIFI-OUI-INFRA: BSSID con bit 'locally assigned' en una red de infraestructura."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import oui_infra

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str) -> NetworkFact:
    return NetworkFact(
        bssid=bssid, ssid=ssid, channel=6, rssi=-60, security="wpa2", first_seen=T0, last_seen=T0
    )


def test_oui_infra_fires_with_locally_assigned_bssid() -> None:
    # 02:.. y 99:.. tienen el bit 0x02 activado (MAC asignada localmente).
    hits = oui_infra.evaluate(
        RuleContext(session_id="s", networks=(_net("02:11:22:33:44:55", "MiFibra-Oficina"),))
    )
    assert len(hits) == 1
    assert hits[0].severidad == "media"
    assert hits[0].evidencia["oui"] == "02:11:22"
    assert "locally assigned" in hits[0].evidencia["motivo"]


def test_oui_infra_negative_globally_assigned_or_non_infra_ssid() -> None:
    ctx = RuleContext(
        session_id="s",
        networks=(
            _net("11:22:33:44:55:01", "MiFibra-Oficina"),
            _net("99:88:77:66:55:44", "Cafe de la esquina"),
        ),
    )
    assert oui_infra.evaluate(ctx) == []
