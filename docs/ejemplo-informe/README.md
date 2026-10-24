# Ejemplo de informe

Ficheros generados por la demo, sin edicion manual:

- `informe-ejemplo.md` — Markdown
- `informe-ejemplo.html` — HTML autocontenido (sin CDN, sin JS)

Regenerarlos:

```bash
m5wireless demo --db data/ejemplo.db --root data/ejemplo-sessions
cp data/ejemplo-sessions/*/report.md docs/ejemplo-informe/informe-ejemplo.md
cp data/ejemplo-sessions/*/report.html docs/ejemplo-informe/informe-ejemplo.html
```

El ejemplo incluye la seccion **Comprobaciones no evaluadas en esta sesion**:
`WIFI-WPS` y `WIFI-CONFIG-DRIFT` no se pudieron aplicar (el firmware no aporta el
flag WPS y no hay sesiones cerradas anteriores). La ausencia de un hallazgo no se
presenta como un cumplimiento.
