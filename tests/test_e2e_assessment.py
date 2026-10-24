"""e2e del flujo de evaluacion (Paso 7, criterio 1 y 5 del MVP).

Recorre el camino real, sin atajos: fixture sintetico -> observaciones en el
store -> sesion creada por la API -> cierre (evalua el catalogo) -> triaje ->
informe Markdown/HTML -> evidencia verificada -> CSV.

No se toca la red: todo ocurre contra `TestClient` y un SQLite en `tmp_path`.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from web_auth import TEST_TOKEN, auth_client

from m5wireless.findings.engine import context_from_fixture, evaluate_session
from m5wireless.models import Client, ClientAssociated, Network, NetworkSeen
from m5wireless.report.evidence import verify_evidence
from m5wireless.store import SQLiteStore
from m5wireless.web import create_app
from m5wireless.web.api import get_store

FIXTURE = Path(__file__).resolve().parents[1] / "src/m5wireless/data/assessment_demo.json"
EXPECTED_RULES = {
    "WIFI-OPEN",
    "WIFI-WEP",
    "WIFI-EVILTWIN",
    "WIFI-CLIENT-OPEN",
    "WIFI-TRANSIENT",
}


def _parse(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=None)


def _load_fixture() -> list:
    """Convertir el fixture en eventos aplicables al store (como haria el colector)."""
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    networks = {
        item["bssid"]: Network(
            bssid=item["bssid"],
            ssid=item.get("ssid"),
            channel=item.get("channel"),
            rssi=item.get("rssi"),
        )
        for item in data["networks"]
    }
    events: list = []
    for row in data["observations"]:
        bssid = row.get("bssid")
        if row["event_type"] == "network_seen":
            network = networks.get(bssid) or Network(
                bssid=bssid, ssid=None, channel=row.get("rssi") and None, rssi=row.get("rssi")
            )
            events.append(
                NetworkSeen(
                    timestamp=_parse(row["timestamp"]),
                    firmware=row.get("firmware", "marauder"),
                    source=row.get("source", "file"),
                    raw_line=row.get("raw_line", ""),
                    network=network,
                )
            )
        elif row["event_type"] == "client_associated":
            events.append(
                ClientAssociated(
                    timestamp=_parse(row["timestamp"]),
                    firmware=row.get("firmware", "marauder"),
                    source=row.get("source", "file"),
                    raw_line=row.get("raw_line", ""),
                    client=Client(mac=row["client_mac"], bssid=bssid),
                )
            )
    return events


@pytest.fixture
def store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "e2e.db")
    for event in _load_fixture():
        store.apply(event)
    yield store
    store.close()


@pytest.fixture
def client(store: SQLiteStore, tmp_path: Path) -> TestClient:
    app = create_app(store, session_token=TEST_TOKEN, data_dir=tmp_path / "data")
    app.dependency_overrides[get_store] = lambda: store
    return auth_client(app)


def test_e2e_fixture_to_report(client: TestClient, store: SQLiteStore, tmp_path: Path) -> None:
    # 1. Crear la sesion (lo que hace el usuario en /evaluacion).
    created = client.post(
        "/api/sessions",
        json={
            "nombre": "Auditoria WiFi e2e",
            "cliente": "Acme",
            "operador": "Sammi",
            "lugar": "Oficina central",
            "alcance": "2.4 y 5 GHz",
            "source": "file",
        },
    )
    assert created.status_code == 201
    session_id = created.json()["id"]

    # 2. Evaluar el catalogo sobre el fixture (lo mismo que hace `m5wireless demo`
    # o la importacion de una captura con metadatos de seguridad).
    evaluate_session(store, replace(context_from_fixture(FIXTURE), session_id=session_id))

    # 3. Cerrar: escribe informe y evidencia.
    closed = client.post(f"/api/sessions/{session_id}/close")
    assert closed.status_code == 200
    assert closed.json()["estado"] == "cerrada"

    # 3. Los 5 hallazgos del fixture, sin duplicados.
    findings = client.get(f"/api/sessions/{session_id}/findings").json()
    assert findings["total"] == 5
    assert {f["rule_id"] for f in findings["findings"]} == EXPECTED_RULES
    assert findings["catalog_version"] == 1
    assert all(f["evidencia"] for f in findings["findings"])
    assert all(f["recomendacion"] for f in findings["findings"])

    # 4. Reevaluar no duplica hallazgos.
    client.post(f"/api/sessions/{session_id}/close")
    again = client.get(f"/api/sessions/{session_id}/findings").json()
    assert again["total"] == 5

    # 5. Triaje: marcar un hallazgo como falso positivo.
    target = next(f for f in findings["findings"] if f["rule_id"] == "WIFI-TRANSIENT")
    triaged = client.patch(f"/api/findings/{target['id']}", json={"estado": "falso_positivo"})
    assert triaged.status_code == 200
    assert triaged.json()["estado"] == "falso_positivo"
    assert (
        client.get(f"/api/sessions/{session_id}/findings?estado=falso_positivo").json()["total"]
        == 1
    )

    # 6. Informe generado sin edicion manual.
    report = client.post(f"/api/sessions/{session_id}/report?fmt=md,html")
    assert report.status_code == 200
    body = report.json()
    assert body["integrity"]["ok"] is True
    assert len(body["written"]) == 3

    markdown = client.get(f"/api/sessions/{session_id}/report?fmt=md").text
    assert "# Informe de evaluacion WiFi: Auditoria WiFi e2e" in markdown
    assert "WIFI-EVILTWIN" in markdown
    assert "falso positivo" in markdown.lower() or "falso_positivo" in markdown.lower()

    html = client.get(f"/api/sessions/{session_id}/report?fmt=html").text
    assert "<script" not in html
    assert "http://" not in html and "https://" not in html

    # 7. Evidencia: hashes de los informes y verificacion independiente.
    evidence = client.get(f"/api/sessions/{session_id}/evidence").json()
    assert evidence["schema"] == "m5wireless/evidence/1"
    assert len(evidence["findings"]) == 5
    assert verify_evidence(tmp_path / "data" / "sessions" / session_id)["ok"] is True

    # 8. CSV para Splunk/Excel.
    csv_res = client.get(f"/api/sessions/{session_id}/findings.csv")
    lines = csv_res.text.splitlines()
    assert len(lines) == 6  # cabecera + 5 hallazgos
    assert lines[0].startswith("session_id,rule_id,rule_version,severidad")

    # 9. Los ficheros existen en la carpeta de la sesion (entregable al cliente).
    directory = tmp_path / "data" / "sessions" / session_id
    assert (directory / "session.json").is_file()
    assert (directory / "report.md").is_file()
    assert (directory / "report.html").is_file()
    assert (directory / "evidence.json").is_file()
    assert (directory / "hashes.json").is_file()


def test_e2e_config_drift_needs_history(client: TestClient, tmp_path: Path) -> None:
    """Sin sesiones previas, `WIFI-CONFIG-DRIFT` no dispara: no se inventa historia."""
    created = client.post("/api/sessions", json={"nombre": "Segunda sesion"}).json()
    client.post(f"/api/sessions/{created['id']}/close")
    rules = {f["rule_id"] for f in client.get("/api/findings").json()["findings"]}
    assert "WIFI-CONFIG-DRIFT" not in rules


def test_e2e_rules_sin_seguridad_no_inventan(store: SQLiteStore) -> None:
    """Honestidad del pipeline: si el store no tiene datos de seguridad, las
    reglas que dependen de ella no disparan, aunque el fixture las contenga."""
    from dataclasses import replace

    from m5wireless.findings.engine import context_from_store, evaluate_session
    from m5wireless.findings.registry import RULES

    ctx = context_from_store(store, "20261024-sin-seguridad")
    assert all(network.security is None for network in ctx.networks)
    fired = {rule.rule_id for rule in RULES for rule in rule.evaluate(ctx)}
    assert {"WIFI-OPEN", "WIFI-WEP", "WIFI-CLIENT-OPEN", "WIFI-WPS"} & fired == set()
    assert "WIFI-EVILTWIN" in fired  # esta no necesita seguridad
    evaluate_session(store, replace(ctx, session_id="20261024-sin-seguridad"))
    assert {f.rule_id for f in store.list_findings(session_id="20261024-sin-seguridad")} == fired
