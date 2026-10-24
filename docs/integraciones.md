# Integraciones (Paso 6)

## Webhooks de evaluacion

Al cerrar una sesion se envia el evento `session.closed`. El destino se
configura solo por entorno o argumento, nunca se hardcodea:

| Variable | Que hace |
|---|---|
| `M5W_WEBHOOK_URL` | URL del webhook (prioridad) |
| `M5W_DISCORD_WEBHOOK` | URL del webhook de Discord, si no hay `M5W_WEBHOOK_URL` |
| `M5W_WEBHOOK_KIND` | `discord` o `generic`; se autodetecta para Discord |
| `M5W_WEBHOOK_ALLOWED_HOSTS` | Allowlist de hosts para `https://` (separados por comas) |

Reglas de seguridad:

- `http://` solo se admite para `127.0.0.1`, `localhost` o `::1`. Un webhook en
  claro fuera de la maquina se rechaza.
- `https://` se admite; si se declara allowlist, el host debe estar en ella.
- Un fallo de envio no rompe el cierre de la sesion: se registra como aviso y,
  en la CLI, devuelve codigo 1.

### Discord

Con una URL de `discord.com/api/webhooks/...` el payload es
`{"content": ..., "embeds": [...]}`: un embed por hallazgo, ordenado por
severidad, con color por severidad (alta roja, media amarilla, azul/info) y
campos Regla, Severidad, Estado, Activo y Recomendacion. Se respetan los
limites de Discord (2000 caracteres de `content`, 4000 de descripcion, 25
embeds).

```powershell
# Windows: la clave vive en la variable de entorno del usuario, no en un fichero
setx M5W_DISCORD_WEBHOOK "https://discord.com/api/webhooks/<id>/<token>"

m5wireless close --session 20261024-demo --webhook "$env:M5W_DISCORD_WEBHOOK"
```

### Formato generic

```json
{
  "event": "session.closed",
  "source": "m5wireless",
  "catalog_version": 1,
  "session": {"id": "...", "nombre": "...", "cliente": "...", "estado": "cerrada"},
  "findings": [{"id": "...", "rule_id": "WIFI-OPEN", "severidad": "alta", "activo": {"bssid": "..."}}],
  "counts": {"total": 5, "alta": 4, "media": 0, "baja": 0, "info": 1}
}
```

## Exportacion CSV de hallazgos

Una fila por hallazgo, lista para Splunk o Excel:

```
session_id,rule_id,rule_version,severidad,titulo,bssid,ssid,client_mac,channel,evidencia,recomendacion,estado,creado
```

La evidencia va como JSON compacto en una columna.

```bash
m5wireless findings --session 20261024-demo --output hallazgos.csv
m5wireless close --session 20261024-demo --csv hallazgos.csv
```

Por API: `GET /api/sessions/{id}/findings.csv` (con `severidad` y `estado`).

## Demo con Docker

```bash
docker compose up
```

Levanta `http://localhost:8000` con una sesion ya cerrada: el fixture
sintetico (`src/m5wireless/data/assessment_demo.json`) genera 5 hallazgos, su
informe Markdown/HTML y `findings.csv`. En 60 segundos hay sesion, hallazgos e
informe descargable.

Sin Docker, la misma demo es local:

```bash
m5wireless demo --serve
```

El middleware solo admite hosts de loopback; si accedes desde otra maquina,
declara `M5W_ALLOWED_HOSTS=mi-host`.
