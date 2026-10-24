"""Tests del fixture de evaluacion (paso 0).

El fixture es la base del catalogo de reglas: si cambia, cambian los hallazgos
esperados. Estos tests no prueban reglas (llegan en el paso 2), solo que el
dataset es coherente con el escenario anunciado:

- una red abierta (que ademas es gemelo malicioso de una WPA2)
- una red WEP
- un SSID duplicado con BSSID distinto
- un cliente asociado a la red abierta
- una red transitoria (vista una sola vez)

y que NO activa las reglas que no deben salir en la demo: WPS, SSID oculto,
congestion de canal, OUI de infraestructura.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from m5wireless.models import normalize_mac

ASSESSMENT_FIXTURES = Path(__file__).parent / "fixtures" / "assessment"

EXPECTED_RULES = {
    "WIFI-OPEN",
    "WIFI-WEP",
    "WIFI-EVILTWIN",
    "WIFI-CLIENT-OPEN",
    "WIFI-TRANSIENT",
}


def _load(name: str) -> dict:
    return json.loads((ASSESSMENT_FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def session() -> dict:
    return _load("sesion_demo.json")


@pytest.fixture(scope="module")
def redes() -> dict:
    return _load("redes.json")


def test_fixture_files_exist(session: dict, redes: dict) -> None:
    assert (ASSESSMENT_FIXTURES / "redes.json").is_file()
    assert (ASSESSMENT_FIXTURES / "sesion_demo.json").is_file()


def test_session_metadata_is_complete(session: dict) -> None:
    for field in (
        "id",
        "nombre",
        "operador",
        "lugar",
        "alcance",
        "dispositivo",
        "source",
        "inicio",
        "fin",
        "estado",
    ):
        assert field in session, f"falta el campo {field} en la sesion demo"
    assert session["estado"] in {"abierta", "cerrada"}
    assert session["source"] in {"serial", "file", "sdcard", "bruce", "bruce-web"}
    datetime.fromisoformat(session["inicio"])
    datetime.fromisoformat(session["fin"])
    assert set(session["expected_findings"]) == EXPECTED_RULES


def test_networks_are_valid_and_mac_normalized(redes: dict) -> None:
    assert len(redes["networks"]) == 5
    for net in redes["networks"]:
        assert net["bssid"] == normalize_mac(net["bssid"])
        assert net["security"] in {"open", "none", "wep", "wpa", "wpa2"}
        assert net["channel"] is None or 1 <= net["channel"] <= 14
        assert net["seen_count"] >= 1


def test_scenario_has_exactly_one_open_and_one_wep(redes: dict) -> None:
    open_nets = [n for n in redes["networks"] if n["security"] in {"open", "none"}]
    wep_nets = [n for n in redes["networks"] if n["security"] == "wep"]
    assert len(open_nets) == 1
    assert len(wep_nets) == 1


def test_evil_twin_pair_is_present(redes: dict) -> None:
    """Dos BSSID distintos, mismo SSID, y seguridad o canal diferente."""
    by_ssid: dict[str, list[dict]] = {}
    for net in redes["networks"]:
        by_ssid.setdefault(net["ssid"], []).append(net)
    twins = [nets for nets in by_ssid.values() if len(nets) > 1]
    assert len(twins) == 1
    a, b = twins[0]
    assert a["bssid"] != b["bssid"]
    assert a["security"] != b["security"] or a["channel"] != b["channel"]
    # La red abierta del gemelo es la misma que dispara WIFI-OPEN.
    assert {a["bssid"], b["bssid"]} >= {
        n["bssid"] for n in redes["networks"] if n["security"] == "open"
    }


def test_client_is_associated_to_the_open_network(redes: dict) -> None:
    open_bssids = {n["bssid"] for n in redes["networks"] if n["security"] in {"open", "none"}}
    associated = {c["bssid"] for c in redes["clients"] if c["bssid"]}
    assert open_bssids & associated
    for client in redes["clients"]:
        assert client["mac"] == normalize_mac(client["mac"])


def test_transient_network_seen_once(redes: dict) -> None:
    transient = [n for n in redes["networks"] if n["seen_count"] == 1]
    assert len(transient) == 1
    assert transient[0]["first_seen"] == transient[0]["last_seen"]


def test_negative_cases_are_absent(redes: dict) -> None:
    """Reglas que no deben dispararse con este fixture."""
    # WPS: ningun parser lo aporta; el fixture lo declara explicitamente falso.
    assert not any(net.get("wps") for net in redes["networks"])
    # SSID oculto: todas las redes tienen nombre.
    assert all(net["ssid"] for net in redes["networks"])
    # Congestion: ninguna red alcanza el umbral de 6 en el mismo canal.
    canales: dict[int, int] = {}
    for net in redes["networks"]:
        canales[net["channel"]] = canales.get(net["channel"], 0) + 1
    assert max(canales.values()) < 6
    # Observaciones coherentes con las redes declaradas.
    bssids = {net["bssid"] for net in redes["networks"]}
    for obs in redes["observations"]:
        assert obs["bssid"] in bssids
        datetime.fromisoformat(obs["timestamp"])
