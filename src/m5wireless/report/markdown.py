"""Informe en Markdown.

Sin dependencias externas. Todo texto de origen no confiable (SSID, nombres de
cliente, recomendaciones) se escape para que un SSID con `#`, `|` o backticks no
rompa la tabla ni se convierta en markdown ejecutable al pegarse en otro sitio.
"""

from __future__ import annotations

from datetime import datetime

from ..models import Finding
from .context import SEVERITY_LABEL, SEVERITY_ORDER, ReportContext


def _dt(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "-"


def _esc(value: object) -> str:
    """Neutralizar caracteres que romperian el Markdown o se convertirian en HTML.

    Los angulares se pasan a entidades HTML: Markdown los renderiza como texto
    literal, no como una etiqueta.
    """
    text = "" if value is None else str(value)
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    for char in ("\\", "`", "*", "_", "#", "|"):
        text = text.replace(char, f"\\{char}")
    return text


def _activo_text(finding: Finding) -> str:
    partes = []
    if finding.activo.bssid:
        partes.append(f"BSSID {finding.activo.bssid}")
    if finding.activo.ssid:
        partes.append(f"SSID {_esc(finding.activo.ssid)}")
    if finding.activo.client_mac:
        partes.append(f"cliente {finding.activo.client_mac}")
    if finding.activo.canal:
        partes.append(f"canal {finding.activo.canal}")
    return ", ".join(partes) or "-"


def render_markdown(ctx: ReportContext) -> str:
    session = ctx.session
    ordered = ctx.ordered_findings()
    lines: list[str] = []

    # Portada
    lines.append(f"# Informe de evaluacion WiFi: {_esc(session.nombre)}")
    lines.append("")
    lines.append(f"- Sesion: `{session.id}`")
    lines.append(f"- Cliente: {_esc(session.cliente) or 'interno'}")
    lines.append(f"- Operador: {_esc(session.operador) or 'no indicado'}")
    lines.append(f"- Lugar: {_esc(session.lugar) or 'no indicado'}")
    lines.append(f"- Dispositivo: {_esc(session.dispositivo) or 'no indicado'}")
    lines.append(f"- Fuente: {session.source}")
    lines.append(f"- Periodo: {_dt(session.inicio)} a {_dt(session.fin)}")
    lines.append(f"- Estado de la sesion: {session.estado}")
    lines.append(f"- Aplicacion: m5wireless {session.version_app or 'sin version'}")
    lines.append(f"- Catalogo de reglas: v{ctx.catalog_version}")
    lines.append(f"- Generado: {ctx.generated_at.isoformat()}")
    lines.append("")

    # Resumen ejecutivo
    grouped = ctx.by_severity()
    total = len(ordered)
    lines.append("## Resumen ejecutivo")
    lines.append("")
    if total == 0:
        lines.append("No se han detectado hallazgos en esta sesion.")
    else:
        lines.append(
            f"Se han detectado **{total} hallazgos** ({len(ctx.open_findings())} abiertos)."
        )
        lines.append("")
        lines.append("| Severidad | Hallazgos |")
        lines.append("|---|---|")
        for sev in SEVERITY_ORDER:
            if grouped[sev]:
                lines.append(f"| {SEVERITY_LABEL[sev]} | {len(grouped[sev])} |")
    lines.append("")

    # Alcance y metodo
    lines.append("## Alcance y metodo")
    lines.append("")
    lines.append(f"- Alcance declarado: {_esc(session.alcance) or 'no declarado'}")
    lines.append(
        f"- Metodo: captura pasiva de redes y clientes mediante firmware de "
        f"auditoria; evaluacion con {len(SEVERITY_ORDER)} categorias de severidad "
        f"y un catalogo determinista de reglas (v{ctx.catalog_version})."
    )
    lines.append(
        f"- Redes observadas: {len(ctx.networks)}; clientes observados: {len(ctx.clients)}; "
        f"observaciones: {len(ctx.observations)}."
    )
    lines.append("")

    # Hallazgos
    lines.append("## Hallazgos")
    lines.append("")
    if not ordered:
        lines.append("Ninguno.")
    else:
        lines.append("| # | Severidad | Regla | Hallazgo | Estado |")
        lines.append("|---|---|---|---|---|")
        for index, finding in enumerate(ordered, start=1):
            lines.append(
                f"| {index} | {SEVERITY_LABEL[finding.severidad]} | `{finding.rule_id}` "
                f"| {_esc(finding.titulo)} | {finding.estado} |"
            )
    lines.append("")

    # Detalle
    lines.append("## Detalle de los hallazgos")
    lines.append("")
    if not ordered:
        lines.append("Ninguno que detallar.")
    for index, finding in enumerate(ordered, start=1):
        lines.append(f"### {index}. {finding.rule_id} ({SEVERITY_LABEL[finding.severidad]})")
        lines.append("")
        lines.append(f"- Titulo: {_esc(finding.titulo)}")
        lines.append(f"- Activo: {_activo_text(finding)}")
        lines.append(f"- Version de la regla: {finding.rule_version}")
        lines.append(f"- Estado de triaje: {finding.estado}")
        lines.append("- Evidencia:")
        if finding.evidencia:
            for key, value in finding.evidencia.items():
                lines.append(f"  - {key}: {_esc(value)}")
        else:
            lines.append("  - (sin evidencia adicional)")
        lines.append(f"- Recomendacion: {_esc(finding.recomendacion) or 'no definida'}")
        lines.append("")

    # Anexo tecnico
    lines.append("## Anexo tecnico")
    lines.append("")
    lines.append("### Redes observadas")
    lines.append("")
    if ctx.networks:
        lines.append("| BSSID | SSID | Canal | RSSI | Seguridad |")
        lines.append("|---|---|---|---|---|")
        for net in sorted(ctx.networks, key=lambda n: n.bssid):
            lines.append(
                f"| `{net.bssid}` | {_esc(net.ssid) or '(oculto)'} | {net.channel or '-'} "
                f"| {net.rssi if net.rssi is not None else '-'} | {net.security or 'no detectada'} |"
            )
    else:
        lines.append("Sin redes registradas.")
    lines.append("")
    lines.append("### Clientes observados")
    lines.append("")
    if ctx.clients:
        lines.append("| MAC | Red asociada |")
        lines.append("|---|---|")
        for client in sorted(ctx.clients, key=lambda c: c.mac):
            lines.append(f"| `{client.mac}` | `{client.bssid or '-'}` |")
    else:
        lines.append("Sin clientes registrados.")
    lines.append("")

    # Limitaciones
    lines.append("## Limitaciones")
    lines.append("")
    lines.append(
        "- La seguridad de cada red solo se evalua si la fuente de datos la aporta. "
        "Los logs de firmware no incluyen campo de seguridad, por lo que las reglas "
        "dependientes (red abierta, WEP, gemelo malicioso) no disparan con logs puros."
    )
    lines.append(
        "- No se realizan pruebas activas: el informe describe lo observado, no lo probado."
    )
    lines.append(
        "- Una red vista una sola vez no puede auditarse; queda como hallazgo informativo."
    )
    lines.append("")

    # Integridad
    lines.append("## Integridad de la evidencia")
    lines.append("")
    if session.artifacts:
        lines.append("| Artefacto | Bytes | SHA-256 |")
        lines.append("|---|---|---|")
        for artifact in session.artifacts:
            lines.append(f"| {_esc(artifact.nombre)} | {artifact.bytes} | `{artifact.sha256}` |")
    else:
        lines.append("Sin artefactos asociados a la sesion.")
    lines.append("")

    # Autoria
    lines.append("## Autoria")
    lines.append("")
    lines.append(f"- Elaborado por: {_esc(session.operador) or 'no indicado'}")
    lines.append(f"- Fecha de generacion: {ctx.generated_at.isoformat()}")
    lines.append("")

    return "\n".join(lines) + "\n"
