"""Reglas del catalogo: una por fichero, todas puras.

Cada fichero expone `RULE_ID`, `RULE_VERSION` y `evaluate(contexto)`.
"""

from __future__ import annotations

from . import (
    channel_congestion,
    client_open,
    config_drift,
    evil_twin,
    hidden_ssid,
    open_network,
    oui_infra,
    transient,
    wep,
    wps,
)

__all__ = [
    "channel_congestion",
    "client_open",
    "config_drift",
    "evil_twin",
    "hidden_ssid",
    "open_network",
    "oui_infra",
    "transient",
    "wep",
    "wps",
]
