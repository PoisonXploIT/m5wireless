"""Tests de la API de sesiones, hallazgos e informe (paso 4).

Criterio de aceptacion: un script externo puede crear una sesion, cerrar la
sesion (que evalua reglas y genera informe) y descargar el informe sin tocar la
UI.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from web_auth import TEST_TOKEN, auth_client

from m5wireless.models import Client, Network, NetworkSeen
from m5wireless.store import MemoryStore
from m5wireless.web import create_app
from m5wireless.web.api import get_store

NOW = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


@pytest.fixture
def seeded_store() -> MemoryStore:
    store = MemoryStore()
    net = Network(bssid="aa:bb:cc:dd:ee:01", ssid="Oficina-A", channel=6, rssi=-60)
    store.apply(
        NetworkSeen(
            timestamp=NOW, firmware="marauder", source="file", raw_line="Found A", network=net
        )
    )
    store.apply(
        NetworkSeen(
            timestamp=datetime(2026, 10, 24, 9, 5, 0, tzinfo=UTC),
            firmware="marauder",
            source="file",
            raw_line="Found A",
            network=net,
        )
    )
    store.upsert_client(Client(mac="aa:aa:aa:aa:aa:01", bssid="aa:bb:cc:dd:ee:01"), at=NOW)
    return store


@pytest.fixture
def client(seeded_store: MemoryStore, tmp_path) -> TestClient:
    app = create_app(seeded_store, session_token=TEST_TOKEN, data_dir=tmp_path / "data")
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        yield test_client


def test_create_session_returns_201_and_slug(client: TestClient) -> None:
    res = client.post(
        "/api/sessions",
        json={
            "nombre": "Auditoria oficina B",
            "cliente": "Acme",
            "operador": "Sammi",
            "alcance": "Redes autorizadas",
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["id"] == "20261024-auditoria-oficina-b"
    assert body["estado"] == "abierta"
    assert body["cliente"] == "Acme"
    assert body["artifacts"] == []


def test_create_session_rejects_bad_source(client: TestClient) -> None:
    res = client.post("/api/sessions", json={"nombre": "x", "source": "telepathy"})
    assert res.status_code == 422


def test_list_sessions_includes_live_session(client: TestClient) -> None:
    res = client.get("/api/sessions")
    assert res.status_code == 200
    body = res.json()
    assert body["live"] is not None
    assert body["live"]["id"].endswith("-viva")
    assert any(s["id"] == body["live"]["id"] for s in body["sessions"])


def test_get_unknown_session_is_404(client: TestClient) -> None:
    assert client.get("/api/sessions/no-existe").status_code == 404


def test_patch_session_metadata(client: TestClient) -> None:
    created = client.post("/api/sessions", json={"nombre": "Oficina"}).json()
    res = client.patch(
        f"/api/sessions/{created['id']}", json={"lugar": "Planta 3", "cliente": "Acme SL"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["lugar"] == "Planta 3"
    assert body["cliente"] == "Acme SL"
    assert body["nombre"] == "Oficina"
    assert client.patch(f"/api/sessions/{created['id']}", json={}).status_code == 200


def test_close_session_evaluates_rules_and_writes_report(client: TestClient, tmp_path) -> None:
    created = client.post("/api/sessions", json={"nombre": "Demo", "operador": "Sammi"}).json()
    session_id = created["id"]
    res = client.post(f"/api/sessions/{session_id}/close")
    assert res.status_code == 200
    closed = res.json()
    assert closed["estado"] == "cerrada"
    assert closed["fin"] is not None

    findings = client.get(f"/api/sessions/{session_id}/findings").json()
    assert findings["total"] >= 1
    rule_ids = {f["rule_id"] for f in findings["findings"]}
    assert "WIFI-TRANSIENT" in rule_ids or "WIFI-OUI-INFRA" in rule_ids

    directory = tmp_path / "data" / "sessions" / session_id
    assert (directory / "report.md").is_file()
    assert (directory / "report.html").is_file()
    assert (directory / "evidence.json").is_file()


def test_report_download_has_content_disposition(client: TestClient) -> None:
    created = client.post("/api/sessions", json={"nombre": "Descarga"}).json()
    session_id = created["id"]
    client.post(f"/api/sessions/{session_id}/close")
    for fmt, media in (("md", "text/markdown"), ("html", "text/html")):
        res = client.get(f"/api/sessions/{session_id}/report?fmt={fmt}")
        assert res.status_code == 200
        assert media in res.headers["content-type"]
        assert (
            f'attachment; filename="report-{session_id}.{fmt}"'
            in res.headers["content-disposition"]
        )
        assert "Informe de evaluacion WiFi" in res.text


def test_report_generation_reports_integrity(client: TestClient) -> None:
    created = client.post("/api/sessions", json={"nombre": "Integridad"}).json()
    client.post(f"/api/sessions/{created['id']}/close")
    res = client.post(f"/api/sessions/{created['id']}/report?fmt=md,html")
    assert res.status_code == 200
    body = res.json()
    assert body["integrity"]["ok"] is True
    assert len(body["written"]) == 3

    # Sin `hashes.json` (sesion abierta, nunca cerrada) la integridad no puede afirmarse.
    abierta = client.post("/api/sessions", json={"nombre": "Abierta"}).json()
    res_abierta = client.post(f"/api/sessions/{abierta['id']}/report?fmt=md")
    assert res_abierta.json()["integrity"]["ok"] is False


def test_findings_global_and_filters(client: TestClient) -> None:
    created = client.post("/api/sessions", json={"nombre": "Filtros"}).json()
    client.post(f"/api/sessions/{created['id']}/close")
    res = client.get("/api/findings")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == len(body["findings"]) >= 1
    assert body["catalog_version"] == 1
    assert client.get("/api/findings?severidad=alta").json()["total"] >= 0
    assert client.get("/api/findings?estado=cerrado").json()["total"] == 0


def test_triage_patch_on_finding(client: TestClient) -> None:
    created = client.post("/api/sessions", json={"nombre": "Triaje"}).json()
    client.post(f"/api/sessions/{created['id']}/close")
    findings = client.get(f"/api/sessions/{created['id']}/findings").json()["findings"]
    fid = findings[0]["id"]
    res = client.patch(f"/api/findings/{fid}", json={"estado": "falso_positivo"})
    assert res.status_code == 200
    assert res.json()["estado"] == "falso_positivo"
    assert client.patch(f"/api/findings/{fid}", json={"estado": "no-existe"}).status_code == 422
    assert client.patch("/api/findings/no-existe", json={"estado": "abierto"}).status_code == 404
    # El triaje sobrevive a una reevaluacion de la misma sesion.
    client.post(f"/api/sessions/{created['id']}/close")
    again = client.get(f"/api/sessions/{created['id']}/findings").json()["findings"]
    assert {f["estado"] for f in again if f["id"] == fid} == {"falso_positivo"}


def test_evidence_endpoint_returns_schema(client: TestClient) -> None:
    created = client.post("/api/sessions", json={"nombre": "Evidencia"}).json()
    client.post(f"/api/sessions/{created['id']}/close")
    res = client.get(f"/api/sessions/{created['id']}/evidence")
    assert res.status_code == 200
    body = res.json()
    assert body["schema"] == "m5wireless/evidence/1"
    assert body["session"]["id"] == created["id"]
    assert isinstance(body["findings"], list)


def test_endpoints_require_token(seeded_store: MemoryStore, tmp_path) -> None:
    from fastapi.testclient import TestClient as PlainClient

    app = create_app(seeded_store, session_token=TEST_TOKEN, data_dir=tmp_path / "data")
    app.dependency_overrides[get_store] = lambda: seeded_store
    plain = PlainClient(app, base_url="http://127.0.0.1:8000")
    assert plain.get("/api/sessions").status_code == 401


def test_existing_endpoints_still_work(client: TestClient) -> None:
    """Compatibilidad: la API anterior no se rompe."""
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/networks").status_code == 200
    assert client.get("/api/clients").status_code == 200
    assert client.get("/api/console").status_code == 200


def test_sqlite_store_works_through_the_api_threadpool(tmp_path) -> None:
    """Regresion: FastAPI ejecuta las rutas sincronas en un threadpool.

    Una conexion SQLite abierta en el hilo principal no puede usarse desde
    otro hilo salvo `check_same_thread=False`. Sin eso, cerrar una sesion
    con SQLite da 500.
    """
    from m5wireless.models import Network, NetworkSeen
    from m5wireless.store import SQLiteStore

    store = SQLiteStore(tmp_path / "api.db")
    net = Network(bssid="11:22:33:44:55:01", ssid="Oficina-A", channel=6, rssi=-60)
    store.apply(
        NetworkSeen(
            timestamp=NOW, firmware="marauder", source="file", raw_line="Found A", network=net
        )
    )
    app = create_app(store, session_token=TEST_TOKEN, data_dir=tmp_path / "data")
    app.dependency_overrides[get_store] = lambda: store
    with auth_client(app) as test_client:
        created = test_client.post("/api/sessions", json={"nombre": "SQLite via API"}).json()
        res = test_client.post(f"/api/sessions/{created['id']}/close")
        assert res.status_code == 200
        findings = test_client.get(f"/api/sessions/{created['id']}/findings").json()
        assert findings["total"] >= 1
        assert test_client.get(f"/api/sessions/{created['id']}/report?fmt=html").status_code == 200
    store.close()
