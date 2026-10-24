# Informe de evaluacion WiFi: Demo de evaluacion

- Sesion: `20261024-demo-de-evaluacion`
- Cliente: Cliente demo
- Operador: m5wireless
- Lugar: no indicado
- Dispositivo: no indicado
- Fuente: file
- Periodo: 2026-10-24T21:03:55.008605+00:00 a 2026-10-24T21:03:55.019590+00:00
- Estado de la sesion: cerrada
- Aplicacion: m5wireless sin version
- Catalogo de reglas: v1
- Generado: 2026-10-24T21:03:55.023603+00:00

## Resumen ejecutivo

Se han detectado **5 hallazgos** (5 abiertos).

| Severidad | Hallazgos |
|---|---|
| Alta | 4 |
| Informativo | 1 |

## Alcance y metodo

- Alcance declarado: no declarado
- Metodo: captura pasiva de redes y clientes mediante firmware de auditoria; evaluacion con 5 categorias de severidad y un catalogo determinista de reglas (v1).
- Redes observadas: 0; clientes observados: 0; observaciones: 0.

## Hallazgos

| # | Severidad | Regla | Hallazgo | Estado |
|---|---|---|---|---|
| 1 | Alta | `WIFI-CLIENT-OPEN` | Cliente aa:aa:aa:aa:aa:01 asociado a una red abierta (Oficina-A) | abierto |
| 2 | Alta | `WIFI-EVILTWIN` | Posible gemelo malicioso de 'Oficina-A' (BSSID a8:bb:cc:dd:ee:01) | abierto |
| 3 | Alta | `WIFI-OPEN` | Red abierta: Oficina-A | abierto |
| 4 | Alta | `WIFI-WEP` | Red con WEP: Legacy-IOT | abierto |
| 5 | Informativo | `WIFI-TRANSIENT` | Red efimera: Cafe-Gratis vista una sola vez | abierto |

## Detalle de los hallazgos

### 1. WIFI-CLIENT-OPEN (Alta)

- Titulo: Cliente aa:aa:aa:aa:aa:01 asociado a una red abierta (Oficina-A)
- Activo: BSSID a8:bb:cc:dd:ee:01, SSID Oficina-A, cliente aa:aa:aa:aa:aa:01
- Version de la regla: 1
- Estado de triaje: abierto
- Evidencia:
  - canal: 1
  - seguridad: open
  - primera_vez: 2026-10-24T09:14:00+00:00
  - ultima_vez: 2026-10-24T09:32:00+00:00
- Recomendacion: Ese dispositivo esta traficando sin cifrado. Localizarlo y conectarlo a una red con WPA2/WPA3, o apagar la red abierta que usa.

### 2. WIFI-EVILTWIN (Alta)

- Titulo: Posible gemelo malicioso de 'Oficina-A' (BSSID a8:bb:cc:dd:ee:01)
- Activo: BSSID 11:22:33:44:55:01, SSID Oficina-A
- Version de la regla: 1
- Estado de triaje: abierto
- Evidencia:
  - ssid_duplicado: Oficina-A
  - bssids: ['11:22:33:44:55:01', 'a8:bb:cc:dd:ee:01']
  - sospechoso: a8:bb:cc:dd:ee:01
  - variantes: [{'bssid': '11:22:33:44:55:01', 'seguridad': 'wpa2', 'canal': 6, 'rssi': -60}, {'bssid': 'a8:bb:cc:dd:ee:01', 'seguridad': 'open', 'canal': 1, 'rssi': -55}]
  - referencia: 11:22:33:44:55:01
- Recomendacion: Verificar fisicamente el punto de acceso. Un SSID legitimo con otro BSSID y seguridad distinta es la firma de un AP falso: los clientes conectados a el salen de la red corporativa.

### 3. WIFI-OPEN (Alta)

- Titulo: Red abierta: Oficina-A
- Activo: BSSID a8:bb:cc:dd:ee:01, SSID Oficina-A
- Version de la regla: 1
- Estado de triaje: abierto
- Evidencia:
  - canal: 1
  - seguridad: open
  - rssi: -55
  - primera_vez: 2026-10-24T09:12:00+00:00
  - ultima_vez: 2026-10-24T09:33:00+00:00
- Recomendacion: Activar WPA2/WPA3 en la red o eliminar la red abierta. Una red sin clave cualquiera puede leerse y asociarse a ella.

### 4. WIFI-WEP (Alta)

- Titulo: Red con WEP: Legacy-IOT
- Activo: BSSID 11:22:33:44:55:02, SSID Legacy-IOT
- Version de la regla: 1
- Estado de triaje: abierto
- Evidencia:
  - canal: 3
  - seguridad: wep
  - rssi: -70
  - primera_vez: 2026-10-24T09:05:00+00:00
  - ultima_vez: 2026-10-24T09:30:00+00:00
- Recomendacion: Migrar a WPA2/WPA3. WEP se rompe en minutos con herramientas de auditoria y no admite parches.

### 5. WIFI-TRANSIENT (Informativo)

- Titulo: Red efimera: Cafe-Gratis vista una sola vez
- Activo: BSSID 22:33:44:55:66:77, SSID Cafe-Gratis
- Version de la regla: 1
- Estado de triaje: abierto
- Evidencia:
  - canal: 12
  - seguridad: wpa2
  - rssi: -90
  - veces_vista: 1
  - primera_vez: 2026-10-24T09:20:00+00:00
  - ultima_vez: 2026-10-24T09:20:00+00:00
- Recomendacion: No se puede evaluar una red que aparece una vez. Si vuelve a aparecer en otra sesion, se reevalua automaticamente.

## Anexo tecnico

### Redes observadas

Sin redes registradas.

### Clientes observados

Sin clientes registrados.

## Comprobaciones no evaluadas en esta sesion

Las siguientes reglas del catalogo no se pudieron aplicar porque la sesion no aporta el dato necesario. **No significa que la red cumpla**: significa que no se ha podido comprobar.

| Regla | Motivo |
|---|---|
| `WIFI-WPS` | ningun parser de firmware entrega el flag WPS; no se puede afirmar que no exista |
| `WIFI-CONFIG-DRIFT` | no hay sesiones cerradas anteriores con las que comparar |

## Limitaciones

- La seguridad de cada red solo se evalua si la fuente de datos la aporta. Los logs de firmware no incluyen campo de seguridad, por lo que las reglas dependientes (red abierta, WEP, gemelo malicioso) no disparan con logs puros.
- No se realizan pruebas activas: el informe describe lo observado, no lo probado.
- Una red vista una sola vez no puede auditarse; queda como hallazgo informativo.

## Integridad de la evidencia

Sin artefactos asociados a la sesion.

## Autoria

- Elaborado por: m5wireless
- Fecha de generacion: 2026-10-24T21:03:55.023603+00:00

