"""WIFI-WPS: solo dispara si la fuente aporta el flag. Caso positivo y negativo.

El caso negativo es el importante: con datos de firmware (sin flag) la regla
no inventa WPS.
"""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import wps

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str, wps: bool) -> NetworkFact:
    return NetworkFact(
        bssid=bssid,
        ssid=ssid,
        channel=1,
        rssi=-60,
        security="wpa2",
        wps=wps,
        first_seen=T0,
        last_seen=T0,
    )


def test_wps_fires_when_the_source_reports_it() -> None:
    hits = wps.evaluate(
        RuleContext(session_id="s", networks=(_net("aa:bb:cc:dd:ee:10", "Con WPS", True),))
    )
    assert len(hits) == 1
    assert hits[0].severidad == "media"
    assert hits[0].evidencia["wps"] is True


def test_wps_negative_firmware_data_has_no_flag() -> None:
    ctx = RuleContext(session_id="s", networks=(_net("aa:bb:cc:dd:ee:11", "Sin WPS", False),))
    assert wps.evaluate(ctx) == []
