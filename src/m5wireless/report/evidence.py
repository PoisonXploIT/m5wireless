"""Evidencia JSON y verificacion de integridad.

`evidence.json` contiene la sesion, los hallazgos y los hashes de los artefactos.
`verify_evidence` recalcula los SHA-256 de la carpeta `artifacts/` y los compara
con `hashes.json`: es el equivalente propio de `sha256sum -c`, sin depender del
sistema operativo.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..models import utc_now
from ..session import sha256_file
from .context import ReportContext


def build_evidence(ctx: ReportContext) -> dict[str, Any]:
    """JSON de evidencia: sesion, hallazgos, anexo y hashes."""
    ordered = ctx.ordered_findings()
    return {
        "schema": "m5wireless/evidence/1",
        "generated": ctx.generated_at.isoformat(),
        "catalog_version": ctx.catalog_version,
        "session": asdict(ctx.session)
        | {
            "inicio": ctx.session.inicio.isoformat(),
            "fin": ctx.session.fin.isoformat() if ctx.session.fin else None,
        },
        "findings": [
            {
                "id": f.id,
                "session_id": f.session_id,
                "rule_id": f.rule_id,
                "rule_version": f.rule_version,
                "severidad": f.severidad,
                "titulo": f.titulo,
                "activo": {k: v for k, v in asdict(f.activo).items() if v is not None},
                "evidencia": f.evidencia,
                "recomendacion": f.recomendacion,
                "estado": f.estado,
                "creado": f.creado.isoformat(),
            }
            for f in ordered
        ],
        "networks": [asdict(n) for n in ctx.networks],
        "clients": [asdict(c) for c in ctx.clients],
        "artifacts": [asdict(a) for a in ctx.session.artifacts],
    }


def write_evidence(session_dir: Path, ctx: ReportContext) -> Path:
    path = Path(session_dir) / "evidence.json"
    path.write_text(
        json.dumps(build_evidence(ctx), indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return path


def verify_evidence(session_dir: Path | str) -> dict[str, Any]:
    """Comprobar que los artefactos de la carpeta coinciden con `hashes.json`.

    Devuelve `{"ok": bool, "comprobados": int, "faltan": [...], "diferentes": [...],
    "sin_hash": [...]}`.
    """
    directory = Path(session_dir)
    hashes_path = directory / "hashes.json"
    if not hashes_path.is_file():
        return {
            "ok": False,
            "error": "no hay hashes.json",
            "comprobados": 0,
            "faltan": [],
            "diferentes": [],
            "sin_hash": [],
        }

    recorded = json.loads(hashes_path.read_text(encoding="utf-8"))
    expected = {a["ruta"]: a for a in recorded.get("artifacts", [])}

    comprobados = 0
    diferentes: list[str] = []
    faltan: list[str] = []
    for ruta, entry in expected.items():
        file = directory / ruta
        if not file.is_file():
            faltan.append(ruta)
            continue
        if sha256_file(file) != entry["sha256"]:
            diferentes.append(ruta)
        else:
            comprobados += 1

    # Artefactos presentes en disco pero no registrados en hashes.json.
    sin_hash: list[str] = []
    artifacts_dir = directory / "artifacts"
    if artifacts_dir.is_dir():
        for file in sorted(artifacts_dir.iterdir()):
            relative = file.relative_to(directory).as_posix()
            if file.is_file() and relative not in expected:
                sin_hash.append(relative)

    return {
        "ok": not diferentes and not faltan and not sin_hash,
        "comprobados": comprobados,
        "faltan": faltan,
        "diferentes": diferentes,
        "sin_hash": sin_hash,
        "generated": recorded.get("generated"),
        "checked_at": utc_now().isoformat(),
    }
