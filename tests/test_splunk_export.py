"""Tests del dialogo de export (X2): alcance filtrado y Splunk HEC.

La conexion real a Splunk no se toca: se sustituye `_hec_request` (el unico
sitio donde se hace HTTP) por un fake que devuelve el status que toque. Asi se
prueban los tres casos del dialogo: sin configurar, HEC caido y HEC OK.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient
from httpx import HTTPError
from web_auth import TEST_TOKEN, auth_client

from m5wireless.exporter.splunk_hec import SplunkHecConfig, SplunkHecExporter
from m5wireless.store import MemoryStore
from m5wireless.web import create_app, splunk_export
from m5wireless.web.api import get_store

HEC_URL = "http://127.0.0.1:8088/services/collector/event"
HEC_TOKEN = "no-se-imprime-jamas"


class FakeResponse:
    """Respuesta minima de httpx: solo interesa el status."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.text = ""


class FakeHec:
    """Registra las peticiones y responde el status pedido."""

    def __init__(self, status_code: int = 200, error: HTTPError | None = None) -> None:
        self.status_code = status_code
        self.error = error
        self.calls: list[dict[str, object]] = []

    def __call__(self, config: object, url: str, *, payload: object | None = None) -> FakeResponse:
        self.calls.append({"url": url, "payload": payload})
        if self.error is not None:
            raise self.error
        return FakeResponse(self.status_code)


@pytest.fixture
def client(seeded_store: MemoryStore) -> TestClient:
    app = create_app(seeded_store, session_token=TEST_TOKEN)
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        yield test_client


@pytest.fixture
def client_with_exporter(seeded_store: MemoryStore) -> TestClient:
    exporter = SplunkHecExporter(
        SplunkHecConfig(url=HEC_URL, token=HEC_TOKEN, batch_size=2, spool_path=None)
    )
    app = create_app(seeded_store, exporter=exporter, session_token=TEST_TOKEN)
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        yield test_client


# ---- alcance (filtrado / todo) ----


def test_export_count_scope_all(client: TestClient) -> None:
    data = client.get("/api/export/count").json()
    assert data["observations"] == 6
    assert data["networks"] == 3
    assert data["scope"] == "all"


def test_export_count_scope_filtered(client: TestClient) -> None:
    data = client.get("/api/export/count", params={"ssid": "cafe"}).json()
    assert data["observations"] == 2  # 1 network_seen + 1 client_associated
    assert data["scope"] == "filtered"


def test_export_csv_applies_filters(client: TestClient) -> None:
    import csv
    import io

    def rows(text: str) -> list[list[str]]:
        return list(csv.reader(io.StringIO(text)))

    todo = rows(client.get("/api/export/csv").text)
    filtrado = rows(client.get("/api/export/csv", params={"ssid": "Movistar"}).text)
    assert len(todo) == 7  # cabecera + 6 observaciones
    assert len(filtrado) == 4  # cabecera + 2 beacon + 1 cliente de Movistar_1A2B
    assert {row[3] for row in filtrado[1:]} == {"network_seen", "client_associated"}


def test_export_json_applies_channel_and_rssi(client: TestClient) -> None:
    canal = client.get("/api/export/json", params={"channel": 11}).json()
    assert len(canal) == 2
    rssi = client.get("/api/export/json", params={"min_rssi": -60}).json()
    assert len(rssi) == 1
    firmware = client.get("/api/export/json", params={"firmware": "evil_m5project"}).json()
    assert len(firmware) == 2
    inexistente = client.get("/api/export/json", params={"ssid": "no-existe"}).json()
    assert inexistente == []


# ---- estado de Splunk ----


def test_status_sin_config(client: TestClient) -> None:
    data = client.get("/api/export/splunk/status").json()
    assert data["configured"] is False
    assert data["queued"] == 0
    assert "token" not in str(data).lower()


def test_status_con_exporter(client_with_exporter: TestClient) -> None:
    data = client_with_exporter.get("/api/export/splunk/status").json()
    assert data["configured"] is True
    assert data["url"] == HEC_URL
    assert data["sourcetype"] == "m5wireless"
    assert HEC_TOKEN not in str(data)


def test_status_por_env(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("M5W_SPLUNK_HEC_URL", HEC_URL)
    monkeypatch.setenv("M5W_SPLUNK_HEC_TOKEN", HEC_TOKEN)
    data = client.get("/api/export/splunk/status").json()
    assert data["configured"] is True
    assert HEC_TOKEN not in str(data)


# ---- prueba de conexion ----


def test_test_conexion_ok(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeHec(status_code=200)
    monkeypatch.setattr(splunk_export, "_hec_request", fake)
    data = client_with_exporter.post("/api/export/splunk/test").json()
    assert data["ok"] is True
    assert "OK" in data["message"]
    # La prueba usa el health check de HEC, no indexa datos.
    assert fake.calls[0]["url"].endswith("/heathcheck")
    assert fake.calls[0]["payload"] is None


def test_test_conexion_sin_config(client: TestClient) -> None:
    data = client.post("/api/export/splunk/test").json()
    assert data["ok"] is False
    assert "no configurado" in data["message"]
    assert data["url"] == ""


def test_test_conexion_hec_caido(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        splunk_export,
        "_hec_request",
        lambda config, url, *, payload=None: (_ for _ in ()).throw(HTTPError("connection refused")),
    )
    res = client_with_exporter.post("/api/export/splunk/test")
    assert res.status_code == 200  # un HEC caido no rompe el dialogo
    data = res.json()
    assert data["ok"] is False
    assert "inalcanzable" in data["message"]


def test_test_conexion_token_malo(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(splunk_export, "_hec_request", FakeHec(status_code=401))
    data = client_with_exporter.post("/api/export/splunk/test").json()
    assert data["ok"] is False
    assert "401" in data["message"]


def test_test_conexion_sin_healthcheck(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Splunk sin `/heathcheck`: vale con que el endpoint de eventos responda."""

    def fake(config: object, url: str, *, payload: object | None = None) -> FakeResponse:
        return FakeResponse(404 if url.endswith("/heathcheck") else 405)

    monkeypatch.setattr(splunk_export, "_hec_request", fake)
    data = client_with_exporter.post("/api/export/splunk/test").json()
    assert data["ok"] is True
    assert "405" in data["message"]


# ---- envio ----


def test_send_sin_config(client: TestClient) -> None:
    res = client.post("/api/export/splunk", json={"format": "json"})
    assert res.status_code == 400
    assert "no configurado" in res.json()["detail"]


def test_send_formato_invalido(client_with_exporter: TestClient) -> None:
    res = client_with_exporter.post("/api/export/splunk", json={"format": "xml"})
    assert res.status_code == 422


def test_send_json_batched(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeHec(status_code=200)
    monkeypatch.setattr(splunk_export, "_hec_request", fake)
    data = client_with_exporter.post(
        "/api/export/splunk", json={"format": "json", "scope": "all"}
    ).json()
    assert data["ok"] is True
    assert data["sent"] == 6 and data["total"] == 6 and data["failed"] == 0
    # batch_size=2 -> 3 peticiones, cada una con su array de eventos.
    assert len(fake.calls) == 3
    assert all(len(call["payload"]) == 2 for call in fake.calls)
    event = fake.calls[0]["payload"][0]["event"]
    assert event["firmware"] in {"marauder", "evil_m5project"}
    assert event["timestamp"]


def test_send_csv_filtered(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeHec(status_code=200)
    monkeypatch.setattr(splunk_export, "_hec_request", fake)
    data = client_with_exporter.post(
        "/api/export/splunk", json={"format": "csv", "scope": "filtered", "ssid": "cafe"}
    ).json()
    assert data["ok"] is True
    assert data["sent"] == 2
    line = fake.calls[0]["payload"][0]["event"]
    assert isinstance(line, str) and "," in line


def test_send_hec_caido_a_mitad(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeHec(status_code=503)
    monkeypatch.setattr(splunk_export, "_hec_request", fake)
    data = client_with_exporter.post(
        "/api/export/splunk", json={"format": "json", "scope": "all"}
    ).json()
    assert data["ok"] is False
    assert data["failed"] == 6
    assert "503" in data["message"]


def test_send_sin_observaciones(
    client_with_exporter: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeHec(status_code=200)
    monkeypatch.setattr(splunk_export, "_hec_request", fake)
    data = client_with_exporter.post(
        "/api/export/splunk", json={"format": "json", "scope": "filtered", "ssid": "no-existe"}
    ).json()
    assert data["ok"] is True
    assert data["sent"] == 0 and data["total"] == 0
    assert fake.calls == []
