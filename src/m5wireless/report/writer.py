"""Escribir el informe y la evidencia en la carpeta de la sesion.

Flujo normal: cerrar sesion -> evaluar reglas -> `write_report` deja
`report.md`, `report.html` y `evidence.json` listos para entregar al cliente.
"""

from __future__ import annotations

from pathlib import Path

from .context import ReportContext
from .evidence import write_evidence
from .html import render_html
from .markdown import render_markdown

FORMATS = ("md", "html")


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
    written.append(write_evidence(directory, ctx))
    return written
