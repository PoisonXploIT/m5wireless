"""WIFI-TRANSIENT: red vista una sola vez."""

from __future__ import annotations

from datetime import UTC, datetime

from m5wireless.findings.base import NetworkFact, RuleContext
from m5wireless.findings.rules import transient
from m5wireless.store.base import ObservationRow

T0 = datetime(2026, 10, 24, 9, 20, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 24, 9, 30, 0, tzinfo=UTC)


def _net(bssid: str, ssid: str, seen_count: int, first: datetime, last: datetime) -> NetworkFact:
    return NetworkFact(
        bssid=bssid,
        ssid=ssid,
        channel=12,
        rssi=-90,
        security="wpa2",
        seen_count=seen_count,
        first_seen=first,
        last_seen=last,
    )


def test_transient_fires_for_a_network_seen_once() -> None:
    ctx = RuleContext(
        session_id="s",
        networks=(_net("22:33:44:55:66:77", "Cafe-Gratis", 1, T0, T0),),
        observations=(
            ObservationRow(
                timestamp=T0,
                firmware="marauder",
                source="file",
                event_type="network_seen",
                bssid="22:33:44:55:66:77",
                rssi=-90,
                client_mac=None,
                raw_line="Found network",
            ),
        ),
    )
    hits = transient.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].severidad == "info"
    assert hits[0].evidencia["veces_vista"] == 1


def test_transient_negative_network_seen_twice() -> None:
    ctx = RuleContext(
        session_id="s",
        networks=(_net("22:33:44:55:66:78", "Estable", 2, T0, T1),),
        observations=(
            ObservationRow(
                timestamp=T0,
                firmware="marauder",
                source="file",
                event_type="network_seen",
                bssid="22:33:44:55:66:78",
                rssi=-90,
                client_mac=None,
                raw_line="Found network",
            ),
            ObservationRow(
                timestamp=T1,
                firmware="marauder",
                source="file",
                event_type="network_seen",
                bssid="22:33:44:55:66:78",
                rssi=-88,
                client_mac=None,
                raw_line="Found network",
            ),
        ),
    )
    assert transient.evaluate(ctx) == []
