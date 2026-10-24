"""Escribir el informe y la evidencia en la carpeta de la sesion.

Flujo normal: cerrar sesion -> evaluar reglas -> `write_report` deja
`report.md`, `report.html` y `evidence.json` listos para entregar al cliente.

Los propios informes se registran en `hashes.json`, de modo que
`verify_evidence` puede afirmar que el documento entregado no se ha tocado.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..session import sha256_file, write_json_atomic
from .context import ReportContext
from .evidence import write_evidence
from .html import render_html
from .markdown import render_markdown

FORMATS = ("md", "html")


def register_report_hashes(directory: Path, paths: list[Path]) -> list[dict[str, object]]:
    """Anadir o actualizar los informes en `hashes.json`.

    Se actualiza el hash (no se omite) porque regenerar el informe cambia su
    contenido: si se guardara el hash antiguo, `verify_evidence` marcaria el
    informe como manipulado cuando simplemente se ha vuelto a generar.
    """
    hashes_path = directory / "hashes.json"
    if hashes_path.is_file():
        recorded = json.loads(hashes_path.read_text(encoding="utf-8"))
    else:
        recorded = {"algorithm": "sha256", "artifacts": []}
    entries = recorded.setdefault("artifacts", [])
    by_ruta = {entry.get("ruta"): entry for entry in entries}
    added: list[dict[str, object]] = []
    for path in paths:
        relative = Path(path).relative_to(directory).as_posix()
        entry = {
            "nombre": Path(path).name,
            "ruta": relative,
            "sha256": sha256_file(path),
            "bytes": Path(path).stat().st_size,
        }
        existing = by_ruta.get(relative)
        if existing is None:
            entries.append(entry)
            added.append(entry)
        else:
            existing.update(entry)
    write_json_atomic(hashes_path, recorded)
    return added


def write_report(
    session_dir: Path | str, ctx: ReportContext, formats: tuple[str, ...] = FORMATS
) -> list[Path]:
    """Generar los ficheros del informe. Devuelve las rutas escritas."""
    directory = Path(session_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        if fmt == "md":
            path = directory / "report.md"
            path.write_text(render_markdown(ctx), encoding="utf-8")
        elif fmt == "html":
            path = directory / "report.html"
            path.write_text(render_html(ctx), encoding="utf-8")
        else:
            raise ValueError(f"formato de informe no soportado: {fmt}")
        written.append(path)
    register_report_hashes(directory, written)
    written.append(write_evidence(directory, ctx))
    return written
