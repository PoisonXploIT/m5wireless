# Instalacion

Index de la documentacion de usuario. El contenido se escribe en el paso 4 del
plan de ejecucion (API) y se cierra en el paso 7.

- [uso.md](uso.md)
- [reglas.md](reglas.md)
- [ejemplo-informe/](ejemplo-informe/) (pendiente, paso 6)

## Vias de instalacion (por documentar)

1. `pip install m5stick-wireless-viewer` (PyPI, nombre sin cambio)
2. `pip install -e .` desde el repo (desarrollo)
3. `docker compose up` (demo con sesion cerrada, paso 6)

Requisitos: Python 3.11 o 3.12. Serial: `pyserial` (opcional, solo para
`--source serial`).
