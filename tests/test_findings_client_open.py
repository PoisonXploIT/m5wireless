"""WIFI-CLIENT-OPEN: cliente asociado a una red abierta."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import ClientFact, NetworkFact, RuleContext
from m5wireless.findings.rules import client_open

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _ctx(client_bssid: str | None) -> RuleContext:
    return RuleContext(
        session_id="s",
        networks=(
            NetworkFact(
                bssid="aa:bb:cc:dd:ee:01",
                ssid="Abierta",
                channel=1,
                rssi=-55,
                security="open",
                first_seen=T0,
                last_seen=T0,
            ),
            NetworkFact(
                bssid="11:22:33:44:55:01",
                ssid="Segura",
                channel=6,
                rssi=-60,
                security="wpa2",
                first_seen=T0,
                last_seen=T0,
            ),
        ),
        clients=(
            ClientFact(mac="aa:aa:aa:aa:aa:01", bssid=client_bssid, first_seen=T0, last_seen=T0),
        ),
    )


def test_client_open_fires() -> None:
    hits = client_open.evaluate(_ctx("aa:bb:cc:dd:ee:01"))
    assert len(hits) == 1
    assert hits[0].severidad == "alta"
    assert hits[0].activo == {
        "bssid": "aa:bb:cc:dd:ee:01",
        "ssid": "Abierta",
        "client_mac": "aa:aa:aa:aa:aa:01",
    }


def test_client_open_negative_client_on_wpa2_or_unassociated() -> None:
    assert client_open.evaluate(_ctx("11:22:33:44:55:01")) == []
    assert client_open.evaluate(_ctx(None)) == []
