"""Tests de los webhooks de evaluacion (Paso 6).

No se toca la red: el `httpx.Client` se sustituye por un stub que registra los
envios. Las pruebas de seguridad (esquema, loopback, allowlist) son las que
importan.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from m5wireless.exporter.webhook import (
    WebhookConfig,
    WebhookConfigError,
    WebhookNotifier,
    build_discord_payload,
    build_generic_payload,
    detect_kind,
    finding_payload,
    resolve_webhook_config,
    validate_url,
)
from m5wireless.models import Active, Finding, Session
from m5wireless.report.findings_csv import CSV_COLUMNS, findings_csv

T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


class StubClient:
    """Cliente HTTP falso que guarda lo enviado."""

    def __init__(self, status: int = 200, text: str = "ok") -> None:
        self.status = status
        self.text = text
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> Any:
        self.calls.append({"url": url, "json": json, "headers": headers})

        class Response:
            def __init__(self, status: int, text: str) -> None:
                self.status_code = status
                self.text = text

        return Response(self.status, self.text)

    def close(self) -> None:
        pass


def _session() -> Session:
    return Session(
        id="20261024-demo",
        nombre="Auditoria WiFi",
        cliente="Acme",
        operador="Sammi",
        inicio=T0,
        fin=T0,
        estado="cerrada",
    )


def _finding(rule_id: str, severidad: str, bssid: str) -> Finding:
    return Finding(
        id=f"{rule_id}-abc",
        session_id="20261024-demo",
        rule_id=rule_id,
        rule_version=1,
        severidad=severidad,
        titulo=f"Hallazgo {rule_id}",
        activo=Active(bssid=bssid, ssid="Oficina-A"),
        evidencia={"canal": 6, "rssi": -60},
        recomendacion="Activar WPA3",
        estado="abierto",
        creado=T0,
    )


# ---- seguridad de la URL ----


def test_http_webhook_only_loopback() -> None:
    validate_url("http://127.0.0.1:8080/hook")
    validate_url("http://localhost:8080/hook")
    with pytest.raises(WebhookConfigError):
        validate_url("http://evil.example.com/hook")


def test_https_webhook_needs_allowlist_when_declared() -> None:
    validate_url("https://hooks.example.com/x")
    validate_url("https://discord.com/api/webhooks/1/2", allowed_hosts=frozenset({"discord.com"}))
    with pytest.raises(WebhookConfigError):
        validate_url("https://evil.example.com/x", allowed_hosts=frozenset({"discord.com"}))


def test_empty_url_rejected() -> None:
    with pytest.raises(WebhookConfigError):
        validate_url("")
    with pytest.raises(WebhookConfigError):
        validate_url("ftp://host/hook")


def test_detect_kind_discord() -> None:
    assert detect_kind("https://discord.com/api/webhooks/123/abc") == "discord"
    assert detect_kind("https://hooks.slack.com/services/x") == "generic"


def test_resolve_config_from_env(monkeypatch) -> None:
    monkeypatch.setenv("M5W_WEBHOOK_URL", "http://127.0.0.1:9000/hook")
    config = resolve_webhook_config()
    assert config is not None
    assert config.kind == "generic"
    # M5W_WEBHOOK_URL tiene prioridad; sin ella se usa el webhook de Discord.
    monkeypatch.delenv("M5W_WEBHOOK_URL")
    monkeypatch.setenv("M5W_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1/2")
    discord = resolve_webhook_config()
    assert discord is not None and discord.kind == "discord"
    monkeypatch.delenv("M5W_DISCORD_WEBHOOK")
    assert resolve_webhook_config() is None


def test_resolve_config_prefers_explicit_url(monkeypatch) -> None:
    monkeypatch.setenv("M5W_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1/2")
    config = resolve_webhook_config(url="http://127.0.0.1:9000/hook")
    assert config is not None and config.url == "http://127.0.0.1:9000/hook"


# ---- payloads ----


def test_generic_payload_has_counts() -> None:
    findings = [
        _finding("WIFI-OPEN", "alta", "aa:bb:cc:dd:ee:01"),
        _finding("WIFI-TRANSIENT", "info", "11:22:33:44:55:01"),
    ]
    payload = build_generic_payload("session.closed", _session(), findings, catalog_version=1)
    assert payload["event"] == "session.closed"
    assert payload["session"]["id"] == "20261024-demo"
    assert payload["counts"]["total"] == 2
    assert payload["counts"]["alta"] == 1
    assert payload["findings"][0]["rule_id"] == "WIFI-OPEN"
    assert payload["findings"][0]["activo"] == {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "Oficina-A"}


def test_discord_payload_orders_by_severity_and_caps_embeds() -> None:
    findings = [_finding(f"WIFI-{i}", "info", f"aa:bb:cc:dd:ee:{i:02d}") for i in range(30)]
    findings.insert(0, _finding("WIFI-OPEN", "alta", "aa:bb:cc:dd:ee:99"))
    payload = build_discord_payload("session.closed", _session(), findings)
    assert len(payload["embeds"]) == 25
    assert payload["embeds"][0]["color"] == 0xE5534B
    assert len(payload["content"]) <= 2000
    assert all(len(embed["description"]) <= 4000 for embed in payload["embeds"])
    assert all(
        len(field["value"]) <= 1000 for embed in payload["embeds"] for field in embed["fields"]
    )


def test_finding_payload_is_serializable() -> None:
    import json

    json.dumps(
        finding_payload(_finding("WIFI-OPEN", "alta", "aa:bb:cc:dd:ee:01")), ensure_ascii=False
    )


# ---- envio ----


def test_notifier_sends_and_records_result() -> None:
    client = StubClient(status=200)
    notifier = WebhookNotifier(
        WebhookConfig(url="https://discord.com/api/webhooks/1/2", kind="discord"), client=client
    )
    result = notifier.notify_session_closed(
        _session(), [_finding("WIFI-OPEN", "alta", "aa:bb:cc:dd:ee:01")]
    )
    assert result["ok"] is True
    assert len(client.calls) == 1
    assert client.calls[0]["url"].startswith("https://discord.com")
    assert notifier.sent[0]["event"] == "session.closed"


def test_notifier_respects_event_filter() -> None:
    client = StubClient()
    config = WebhookConfig(url="https://hooks.example.com/x", events=("finding.created",))
    notifier = WebhookNotifier(config, client=client)
    result = notifier.send("session.closed", _session(), [])
    assert result["ok"] is False
    assert client.calls == []


def test_notifier_reports_failure_without_raising() -> None:
    class FailingClient:
        def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> Any:
            raise httpx.HTTPError("conexión rechazada")

        def close(self) -> None:
            pass

    notifier = WebhookNotifier(
        WebhookConfig(url="https://hooks.example.com/x", retries=0), client=FailingClient()
    )
    result = notifier.notify_session_closed(_session(), [])
    assert result["ok"] is False
    assert "conexión rechazada" in result["detail"]


# ---- CSV de hallazgos ----


def test_findings_csv_columns_and_rows() -> None:
    csv_text = findings_csv([_finding("WIFI-OPEN", "alta", "aa:bb:cc:dd:ee:01")])
    lines = csv_text.splitlines()
    assert lines[0] == ",".join(CSV_COLUMNS)
    assert len(lines) == 2
    assert "WIFI-OPEN" in lines[1]
    assert '""canal"":6' in lines[1]  # la evidencia JSON va entre comillas escapadas


def test_findings_csv_escapes_commas_in_evidence() -> None:
    finding = Finding(
        id="WIFI-OPEN-x",
        session_id="s",
        rule_id="WIFI-OPEN",
        rule_version=1,
        severidad="alta",
        titulo="Red abierta, SSID con coma",
        activo=Active(bssid="aa:bb:cc:dd:ee:01"),
        evidencia={"nota": "uno, dos", "canal": 6},
        recomendacion="Segmentar",
        estado="abierto",
        creado=T0,
    )
    row = findings_csv([finding]).splitlines()[1]
    assert '"uno, dos"' in row
