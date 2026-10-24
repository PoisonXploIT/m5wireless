"""Informe de evaluacion (Fase A, paso 3).

Markdown y HTML autocontenido (CSS embebido, sin CDN, sin JS) + evidencia JSON
verificable con hashes. No se usa WeasyPrint ni ninguna dependencia externa: el
PDF se genera solo si un cliente lo exige.
"""

from __future__ import annotations

from .context import ReportContext, build_context
from .evidence import build_evidence, verify_evidence, write_evidence
from .html import render_html
from .markdown import render_markdown
from .writer import FORMATS, write_report

__all__ = [
    "FORMATS",
    "ReportContext",
    "build_context",
    "build_evidence",
    "render_html",
    "render_markdown",
    "verify_evidence",
    "write_evidence",
    "write_report",
]
