# Uso

Index. Pendiente de redactar en los pasos 4-7; aqui se fija la estructura para
que la UI y la CLI documenten lo mismo.

1. Conectar el dispositivo (Marauder / Evil-M5Project / Bruce) o importar un log.
2. Crear una sesion: nombre, cliente, operador, lugar y alcance legal.
3. Dejar que la sesion acumule observaciones (sesion viva implicita si no se crea).
4. Cerrar la sesion: se evaluan las reglas y se genera el informe.
5. Triaje de hallazgos: aceptar, marcar falso positivo o corregido.
6. Descargar el informe (Markdown o HTML) y la evidencia (JSON + hashes).

## Consola de evaluacion (`/evaluacion`)

Abre `http://127.0.0.1:8000/evaluacion` tras `m5wireless run`. La pagina tiene
cuatro bloques: **Sesion**, **Contadores**, **Hallazgos** e **Informe**.

Flujo de triaje (menos de 5 minutos en una sesion de laboratorio):

1. Rellenar nombre, cliente, operador, lugar y alcance; pulsar **Crear sesion**.
2. Ver observaciones en `/` (Redes) o importar un pcap con **Importar**.
3. Pulsar **Cerrar y evaluar**: se ejecutan las 10 reglas del catalogo, se
   escriben `report.md`, `report.html` y `evidence.json`.
4. En **Hallazgos**, filtrar por severidad o estado y marcar cada hallazgo como
   `abierto`, `aceptado`, `falso positivo` o `corregido`. El triaje sobrevive a
   reevaluaciones posteriores de la misma sesion.
5. En **Informe**, pulsar **Generar informe** y descargar Markdown o HTML. La
   linea de integridad confirma que los hashes de `hashes.json` (artefactos
   crudos y los propios informes) coinciden.

El selector de sesion permite volver a una sesion cerrada anterior para revisar
su triaje sin perder el trabajo.

## Panel tecnico del dashboard

En `/`, los contadores (redes, clientes, fuente, pipeline) y la distribucion por
canal estan dentro de **Panel tecnico**, plegado por defecto. La tabla de redes
es lo primero que se ve; el detalle se consulta bajo demanda.

## CLI

```bash
m5wireless report --session 20261024-demo --fmt md,html
m5wireless close --session 20261024-demo --csv hallazgos.csv
m5wireless findings --session 20261024-demo --output hallazgos.csv
m5wireless deliver --session 20261024-demo --cliente Acme --dest C:\Auditorias-WiFi
m5wireless demo --serve
```

`deliver` copia la carpeta de la sesion a `<dest>/<cliente>/<fecha>/` solo si la
sesion esta **cerrada** y la evidencia verifica; no sobrescribe sin `--force`.
La raiz puede fijarse con `M5W_DELIVER_DIR`.

Un ejemplo real generado por la demo esta en
[ejemplo-informe/](ejemplo-informe/).

Las integraciones externas (webhooks, CSV para Splunk, demo Docker) estan en
[docs/integraciones.md](integraciones.md).

La CLI escribe en `data/sessions/<id>/` y devuelve `0` si la integridad de la
evidencia se verifica, `1` si hay problemas (hashes que no coinciden, ficheros
faltantes o artefactos sin registrar).

## API

| Metodo | Ruta | Que hace |
|---|---|---|
| GET | `/api/sessions` | Lista sesiones y la sesion viva |
| POST | `/api/sessions` | Crea una sesion |
| GET | `/api/sessions/{id}` | Detalle de una sesion |
| PATCH | `/api/sessions/{id}` | Edita metadatos |
| POST | `/api/sessions/{id}/close` | Evalua reglas, cierra y genera informe |
| GET | `/api/sessions/{id}/findings` | Hallazgos de la sesion (filtros `severidad`, `estado`) |
| GET | `/api/findings` | Hallazgos de todas las sesiones |
| PATCH | `/api/findings/{id}` | Triaje |
| POST | `/api/sessions/{id}/report?fmt=md,html` | Genera el informe y verifica integridad |
| GET | `/api/sessions/{id}/report?fmt=md\|html` | Descarga el informe |
| GET | `/api/sessions/{id}/evidence` | Evidencia JSON, hashes y verificacion |

Todas las rutas `/api/*` exigen la cookie de sesion `m5w_ui` (se siembra al
visitar `/` o `/evaluacion`) o la cabecera `X-M5W-Token`.
