# Catalogo de reglas de hallazgos

Index del catalogo. Cada regla tiene `rule_id`, severidad, entrada, logica,
recomendacion y un fixture de prueba con su caso negativo. La logica detallada
vive en el codigo (`src/m5wireless/findings/rules/`); esta tabla es la
referencia para el lector del informe.

Regla de oro: **si el dato no existe en el pipeline, la regla no se escribe**.
No se infiere lo que el firmware no entrega.

| rule_id | Sev | Entrada | Logica (resumen) | Estado |
|---|---|---|---|---|
| WIFI-OPEN | alta | Network | seguridad `open`/`none` | implementada |
| WIFI-WEP | alta | Network | seguridad `wep` | implementada |
| WIFI-WPS | media | Network | flag `wps` si el parser lo aporta | aplazada: ningun parser actual entrega WPS |
| WIFI-HIDDEN | info | Network | SSID vacio con BSSID visible | implementada |
| WIFI-EVILTWIN | alta | Network | mismo SSID, BSSID distinto y (seguridad o canal distinto) | implementada |
| WIFI-CLIENT-OPEN | alta | Network + Client | cliente asociado a una red abierta | implementada |
| WIFI-OUI-INFRA | media | Network + OUI | BSSID con OUI de movil/virtual en red de infraestructura | implementada |
| WIFI-CHANNEL-CONGESTION | baja | Network | >= 6 redes en el mismo canal | implementada |
| WIFI-TRANSIENT | info | historial | red vista una sola vez y no vuelve | implementada |
| WIFI-CONFIG-DRIFT | media | 2 sesiones | mismo BSSID cambia seguridad o canal | implementada |

`rule_version` sube cuando cambia la logica de una regla; el `id` del hallazgo
es `rule_id + hash(activo)` y se mantiene estable entre ejecuciones.
