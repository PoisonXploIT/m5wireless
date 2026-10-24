"""Informe en HTML autocontenido.

CSS embebido, sin CDN, sin JavaScript, sin fuentes externas. Todo el contenido
procedente de datos observados (SSID, MAC, nombres) pasa por `html.escape`, de
modo que un SSID como `<img onerror=...>` se muestra como texto y no se ejecuta.
"""

from __future__ import annotations

import html

from ..models import Finding
from .context import SEVERITY_LABEL, SEVERITY_ORDER, ReportContext

_CSS = """
:root {
  --ink: #1c1c1c;
  --muted: #5a5a5a;
  --line: #d6d6d6;
  --critica: #8b1a1a;
  --alta: #b02a2a;
  --media: #8a6d1a;
  --baja: #2f6b4f;
  --info: #33506b;
}
* { box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: var(--ink);
  margin: 0;
  padding: 24px;
  line-height: 1.45;
  max-width: 900px;
}
h1 { font-size: 1.5rem; margin-bottom: 4px; }
h2 { font-size: 1.15rem; margin-top: 28px; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
h3 { font-size: 1rem; margin-top: 18px; }
p, li { font-size: 0.92rem; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 0.88rem; }
th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
code { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 0.85rem; }
.meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 18px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 0.8rem; }
.badge-critica { background: var(--critica); }
.badge-alta { background: var(--alta); }
.badge-media { background: var(--media); }
.badge-baja { background: var(--baja); }
.badge-info { background: var(--info); }
.finding { border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; margin: 12px 0; }
.empty { color: var(--muted); }
.gap-note { background: #fff7e6; border: 1px solid var(--media); border-radius: 6px; padding: 10px 12px; color: #1f2933; }
@media (max-width: 420px) { body { padding: 14px; } table { font-size: 0.8rem; } }
"""


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _activo_text(finding: Finding) -> str:
    partes = []
    if finding.activo.bssid:
        partes.append(f"BSSID {finding.activo.bssid}")
    if finding.activo.ssid:
        partes.append(f"SSID {finding.activo.ssid}")
    if finding.activo.client_mac:
        partes.append(f"cliente {finding.activo.client_mac}")
    if finding.activo.canal:
        partes.append(f"canal {finding.activo.canal}")
    return ", ".join(partes) or "-"


def render_html(ctx: ReportContext) -> str:
    session = ctx.session
    ordered = ctx.ordered_findings()
    grouped = ctx.by_severity()
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="es">',
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>Informe de evaluacion WiFi: {_esc(session.nombre)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        f"<h1>Informe de evaluacion WiFi: {_esc(session.nombre)}</h1>",
        "<div class='meta'>",
        (
            f"Sesion {_esc(session.id)} | cliente {_esc(session.cliente) or 'interno'} | "
            f"periodo {_esc(session.inicio.isoformat())} a "
            f"{_esc(session.fin.isoformat()) if session.fin else 'abierto'} | "
            f"catalogo de reglas v{ctx.catalog_version} | generado {ctx.generated_at.isoformat()}"
        ),
        "</div>",
        "<h2>Resumen ejecutivo</h2>",
    ]

    if not ordered:
        out.append("<p class='empty'>No se han detectado hallazgos en esta sesion.</p>")
    else:
        out.append(
            f"<p>Se han detectado <strong>{len(ordered)}</strong> hallazgos "
            f"({len(ctx.open_findings())} abiertos).</p>"
        )
        out.append("<table><tr><th>Severidad</th><th>Hallazgos</th></tr>")
        for sev in SEVERITY_ORDER:
            if grouped[sev]:
                out.append(f"<tr><td>{SEVERITY_LABEL[sev]}</td><td>{len(grouped[sev])}</td></tr>")
        out.append("</table>")

    out.extend(
        [
            "<h2>Alcance y metodo</h2>",
            f"<p>Alcance declarado: {_esc(session.alcance) or 'no declarado'}</p>",
            (
                f"<p>Redes observadas: {len(ctx.networks)}. Clientes observados: {len(ctx.clients)}. "
                f"Observaciones: {len(ctx.observations)}.</p>"
            ),
            "<h2>Hallazgos</h2>",
        ]
    )
    if not ordered:
        out.append("<p class='empty'>Ninguno.</p>")
    else:
        out.append(
            "<table><tr><th>#</th><th>Severidad</th><th>Regla</th><th>Hallazgo</th><th>Estado</th></tr>"
        )
        for index, finding in enumerate(ordered, start=1):
            out.append(
                f"<tr><td>{index}</td>"
                f"<td><span class='badge badge-{finding.severidad}'>{SEVERITY_LABEL[finding.severidad]}</span></td>"
                f"<td><code>{_esc(finding.rule_id)}</code></td>"
                f"<td>{_esc(finding.titulo)}</td>"
                f"<td>{_esc(finding.estado)}</td></tr>"
            )
        out.append("</table>")

    out.append("<h2>Detalle de los hallazgos</h2>")
    if not ordered:
        out.append("<p class='empty'>Ninguno que detallar.</p>")
    for index, finding in enumerate(ordered, start=1):
        out.append("<div class='finding'>")
        out.append(
            f"<h3>{index}. {_esc(finding.rule_id)} "
            f"<span class='badge badge-{finding.severidad}'>{SEVERITY_LABEL[finding.severidad]}</span></h3>"
        )
        out.append(f"<p><strong>Titulo:</strong> {_esc(finding.titulo)}</p>")
        out.append(f"<p><strong>Activo:</strong> {_esc(_activo_text(finding))}</p>")
        out.append("<p><strong>Evidencia:</strong></p><ul>")
        if finding.evidencia:
            for key, value in finding.evidencia.items():
                out.append(f"<li>{_esc(key)}: {_esc(value)}</li>")
        else:
            out.append("<li>(sin evidencia adicional)</li>")
        out.append("</ul>")
        out.append(
            f"<p><strong>Recomendacion:</strong> {_esc(finding.recomendacion) or 'no definida'}</p>"
        )
        out.append("</div>")

    out.append("<h2>Anexo tecnico</h2>")
    out.append("<h3>Redes observadas</h3>")
    if ctx.networks:
        out.append(
            "<table><tr><th>BSSID</th><th>SSID</th><th>Canal</th><th>RSSI</th><th>Seguridad</th></tr>"
        )
        for net in sorted(ctx.networks, key=lambda n: n.bssid):
            out.append(
                f"<tr><td><code>{_esc(net.bssid)}</code></td><td>{_esc(net.ssid) or '(oculto)'}</td>"
                f"<td>{_esc(net.channel)}</td><td>{_esc(net.rssi)}</td>"
                f"<td>{_esc(net.security) or 'no detectada'}</td></tr>"
            )
        out.append("</table>")
    else:
        out.append("<p class='empty'>Sin redes registradas.</p>")

    out.append("<h3>Clientes observados</h3>")
    if ctx.clients:
        out.append("<table><tr><th>MAC</th><th>Red asociada</th></tr>")
        for client in sorted(ctx.clients, key=lambda c: c.mac):
            out.append(
                f"<tr><td><code>{_esc(client.mac)}</code></td><td><code>{_esc(client.bssid)}</code></td></tr>"
            )
        out.append("</table>")
    else:
        out.append("<p class='empty'>Sin clientes registrados.</p>")

    if ctx.gaps:
        out.append("<h2>Comprobaciones no evaluadas en esta sesion</h2>")
        out.append(
            "<p class='gap-note'>Las siguientes reglas del catalogo no se pudieron aplicar "
            "porque la sesion no aporta el dato necesario. <strong>No significa que la red "
            "cumpla</strong>: significa que no se ha podido comprobar.</p>"
        )
        out.append("<table><tr><th>Regla</th><th>Motivo</th></tr>")
        for gap in ctx.gaps:
            out.append(
                f"<tr><td><code>{_esc(gap['rule_id'])}</code></td>"
                f"<td>{_esc(gap['motivo'])}</td></tr>"
            )
        out.append("</table>")

    out.extend(
        [
            "<h2>Limitaciones</h2>",
            (
                "<p>La seguridad de cada red solo se evalua si la fuente de datos la aporta. "
                "Los logs de firmware no incluyen campo de seguridad, por lo que las reglas "
                "dependientes no disparan con logs puros.</p>"
            ),
            "<p>No se realizan pruebas activas: el informe describe lo observado, no lo probado.</p>",
            "<h2>Integridad de la evidencia</h2>",
        ]
    )
    if session.artifacts:
        out.append("<table><tr><th>Artefacto</th><th>Bytes</th><th>SHA-256</th></tr>")
        for artifact in session.artifacts:
            out.append(
                f"<tr><td>{_esc(artifact.nombre)}</td><td>{artifact.bytes}</td>"
                f"<td><code>{_esc(artifact.sha256)}</code></td></tr>"
            )
        out.append("</table>")
    else:
        out.append("<p class='empty'>Sin artefactos asociados a la sesion.</p>")

    out.extend(
        [
            "<h2>Autoria</h2>",
            (
                f"<p>Elaborado por {_esc(session.operador) or 'no indicado'}. "
                f"Fecha de generacion: {ctx.generated_at.isoformat()}.</p>"
            ),
            "</body>",
            "</html>",
        ]
    )
    return "\n".join(out) + "\n"
