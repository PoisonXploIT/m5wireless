"""Exportacion de hallazgos a CSV (Paso 6), pensada para Splunk/Excel.

Una fila por hallazgo. La evidencia va como JSON compacto en una sola columna
para no romper el CSV con comas internas.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path

from ..models import Finding

CSV_COLUMNS = (
    "session_id",
    "rule_id",
    "rule_version",
    "severidad",
    "titulo",
    "bssid",
    "ssid",
    "client_mac",
    "channel",
    "evidencia",
    "recomendacion",
    "estado",
    "creado",
)


def finding_row(finding: Finding) -> dict[str, str]:
    activo = asdict(finding.activo)
    return {
        "session_id": finding.session_id,
        "rule_id": finding.rule_id,
        "rule_version": str(finding.rule_version),
        "severidad": finding.severidad,
        "titulo": finding.titulo,
        "bssid": activo.get("bssid", ""),
        "ssid": activo.get("ssid", ""),
        "client_mac": activo.get("client_mac", ""),
        "channel": activo.get("channel", ""),
        "evidencia": json.dumps(finding.evidencia, ensure_ascii=False, separators=(",", ":")),
        "recomendacion": finding.recomendacion,
        "estado": finding.estado,
        "creado": finding.creado.isoformat(),
    }


def findings_csv(findings: Iterable[Finding]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS))
    writer.writeheader()
    for finding in findings:
        writer.writerow(finding_row(finding))
    return buffer.getvalue()


def write_findings_csv(path: Path | str, findings: Iterable[Finding]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(findings_csv(findings), encoding="utf-8", newline="")
    return target
