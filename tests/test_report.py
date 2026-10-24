"""Tests del informe y la evidencia (paso 3).

Criterios de aceptacion: informe listo sin edicion manual con 0, 1 y N
hallazgos; SSID malicioso escapado; HTML autocontenido; hashes estables y
verificables.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from m5wireless.findings.base import ClientFact, NetworkFact
from m5wireless.models import Active, Artifact, Finding, Session
from m5wireless.report import (
    build_evidence,
    render_html,
    render_markdown,
    verify_evidence,
    write_report,
)
from m5wireless.report.context import ReportContext

GENERATED = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
T0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)


def _session(**overrides) -> Session:
    base = {
        "id": "20261024-demo",
        "nombre": "Auditoria WiFi demo",
        "cliente": "Acme",
        "operador": "Sammi",
        "lugar": "Oficina",
        "alcance": "Redes autorizadas del laboratorio",
        "dispositivo": "marauder-m5stick-1",
        "source": "file",
        "inicio": T0,
        "fin": T0,
        "estado": "cerrada",
        "version_app": "3.5.0",
    }
    base.update(overrides)
    return Session(**base)


def _finding(rule_id: str, severidad: str, titulo: str, bssid: str) -> Finding:
    from m5wireless.models import make_finding_id

    activo = Active(bssid=bssid)
    return Finding(
        id=make_finding_id(rule_id, activo),
        session_id="20261024-demo",
        rule_id=rule_id,
        rule_version=1,
        severidad=severidad,
        titulo=titulo,
        activo=activo,
        evidencia={"canal": 6},
        recomendacion="Revisar el AP.",
    )


def _context(findings: tuple[Finding, ...], session: Session | None = None) -> ReportContext:
    return ReportContext(
        session=session or _session(),
        findings=findings,
        networks=(
            NetworkFact(
                bssid="aa:bb:cc:dd:ee:01", ssid="Oficina-A", channel=6, rssi=-60, security="wpa2"
            ),
        ),
        clients=(ClientFact(mac="aa:aa:aa:aa:aa:01", bssid="aa:bb:cc:dd:ee:01"),),
        observations=(),
        catalog_version=1,
        generated_at=GENERATED,
    )


def test_report_with_zero_findings() -> None:
    ctx = _context(())
    md = render_markdown(ctx)
    html = render_html(ctx)
    assert "No se han detectado hallazgos" in md
    assert "No se han detectado hallazgos" in html
    assert "| # | Severidad" not in md
    assert "Resumen ejecutivo" in md and "Limitaciones" in md


def test_report_with_one_finding() -> None:
    ctx = _context((_finding("WIFI-OPEN", "alta", "Red abierta", "aa:bb:cc:dd:ee:01"),))
    md = render_markdown(ctx)
    assert "**1 hallazgos**" in md or "1 hallazgos" in md
    assert "WIFI-OPEN" in md
    assert "Alta" in md


def test_report_with_many_findings_is_ordered_by_severity() -> None:
    findings = (
        _finding("WIFI-TRANSIENT", "info", "Red efimera", "22:33:44:55:66:77"),
        _finding("WIFI-OPEN", "alta", "Red abierta", "aa:bb:cc:dd:ee:01"),
        _finding("WIFI-WEP", "alta", "Red WEP", "11:22:33:44:55:02"),
    )
    ctx = _context(tuple(sorted(findings, key=lambda f: f.id)))
    md = render_markdown(ctx)
    positions = [md.index(name) for name in ("Red abierta", "Red WEP", "Red efimera")]
    assert positions == sorted(positions)


def test_malicious_ssid_is_escaped_in_html() -> None:
    ctx = ReportContext(
        session=_session(),
        findings=(),
        networks=(
            NetworkFact(
                bssid="aa:bb:cc:dd:ee:09",
                ssid="<img onerror=alert(1)>",
                channel=1,
                rssi=-50,
                security="open",
            ),
        ),
        clients=(),
        observations=(),
        catalog_version=1,
        generated_at=GENERATED,
    )
    html = render_html(ctx)
    assert "<img onerror" not in html
    assert "&lt;img onerror=alert(1)&gt;" in html
    md = render_markdown(ctx)
    assert "<img onerror" not in md
    assert "&lt;img onerror=alert(1)&gt;" in md


def test_html_is_self_contained() -> None:
    html = render_html(
        _context((_finding("WIFI-OPEN", "alta", "Red abierta", "aa:bb:cc:dd:ee:01"),))
    )
    assert "<script" not in html
    assert "http://" not in html and "https://" not in html
    assert "<style>" in html
    assert html.startswith("<!DOCTYPE html>")


def test_evidence_hashes_are_stable() -> None:
    ctx = _context((_finding("WIFI-OPEN", "alta", "Red abierta", "aa:bb:cc:dd:ee:01"),))
    first = json.dumps(build_evidence(ctx), sort_keys=True)
    second = json.dumps(build_evidence(ctx), sort_keys=True)
    assert first == second
    evidence = json.loads(first)
    assert evidence["schema"] == "m5wireless/evidence/1"
    assert len(evidence["findings"]) == 1


def test_write_report_and_verify_evidence(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True)
    (artifacts / "captura.log").write_bytes(b"Found network: Ch: 6\n")
    digest = __import__("hashlib").sha256(b"Found network: Ch: 6\n").hexdigest()
    session = _session(artifacts=(Artifact("captura.log", "artifacts/captura.log", digest, 20),))
    (tmp_path / "hashes.json").write_text(
        json.dumps(
            {
                "generated": GENERATED.isoformat(),
                "algorithm": "sha256",
                "artifacts": [
                    {
                        "nombre": "captura.log",
                        "ruta": "artifacts/captura.log",
                        "sha256": digest,
                        "bytes": 20,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    ctx = _context((_finding("WIFI-OPEN", "alta", "Red abierta", "aa:bb:cc:dd:ee:01"),), session)
    written = write_report(tmp_path, ctx)
    names = {p.name for p in written}
    assert {"report.md", "report.html", "evidence.json"} <= names
    check = verify_evidence(tmp_path)
    assert check["ok"] is True
    assert check["comprobados"] == 1

    # Manipular el artefacto rompe la verificacion.
    (artifacts / "captura.log").write_bytes(b"Found network: Ch: 6 (alterado)\n")
    broken = verify_evidence(tmp_path)
    assert broken["ok"] is False
    assert broken["diferentes"] == ["artifacts/captura.log"]


def test_verify_evidence_detects_missing_and_unregistered_files(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True)
    (artifacts / "a.log").write_bytes(b"a")
    (artifacts / "b.log").write_bytes(b"b")
    import hashlib

    (tmp_path / "hashes.json").write_text(
        json.dumps(
            {
                "generated": GENERATED.isoformat(),
                "algorithm": "sha256",
                "artifacts": [
                    {
                        "nombre": "a.log",
                        "ruta": "artifacts/a.log",
                        "sha256": hashlib.sha256(b"a").hexdigest(),
                        "bytes": 1,
                    },
                    {
                        "nombre": "c.log",
                        "ruta": "artifacts/c.log",
                        "sha256": hashlib.sha256(b"c").hexdigest(),
                        "bytes": 1,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    result = verify_evidence(tmp_path)
    assert result["ok"] is False
    assert result["faltan"] == ["artifacts/c.log"]
    assert result["sin_hash"] == ["artifacts/b.log"]


def test_report_cli_writes_files_for_the_demo_session(tmp_path: Path) -> None:
    from dataclasses import replace

    from m5wireless.cli import main
    from m5wireless.findings.engine import context_from_fixture, evaluate_session
    from m5wireless.session import close_session, create_session
    from m5wireless.store import SQLiteStore

    db = tmp_path / "demo.db"
    root = tmp_path / "sessions"
    store = SQLiteStore(db)
    fixture = Path(__file__).parent / "fixtures" / "assessment" / "redes.json"
    ctx = replace(context_from_fixture(fixture), session_id="20261024-demo")
    session = create_session(
        store, "Auditoria WiFi demo", root=root, inicio=T0, session_id="20261024-demo"
    )
    evaluate_session(store, ctx)
    close_session(store, session.id, root=root, closed_at=T0)
    store.close()

    code = main(["report", "--session", "20261024-demo", "--db", str(db), "--root", str(root)])
    assert code == 0
    assert (root / "20261024-demo" / "report.md").is_file()
    assert (root / "20261024-demo" / "report.html").is_file()
    assert (root / "20261024-demo" / "evidence.json").is_file()


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_single_format_works(fmt: str) -> None:
    ctx = _context((_finding("WIFI-OPEN", "alta", "Red abierta", "aa:bb:cc:dd:ee:01"),))
    text = render_markdown(ctx) if fmt == "md" else render_html(ctx)
    assert "WIFI-OPEN" in text
