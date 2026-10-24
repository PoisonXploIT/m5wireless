# Instalacion

Index de la documentacion de usuario.

## Vias de instalacion

1. **Desde el repo (recomendado ahora mismo):**
   ```bash
   git clone https://github.com/PoisonXploIT/m5wireless.git
   cd m5wireless
   pip install .                 # core + CLI
   pip install ".[serial,web,splunk]"   # completo
   ```
2. **PyPI:** `pip install m5stick-wireless-viewer`.
   **Ojo:** en PyPI la ultima version publicada es **3.4.0**. La 3.5.0 (consola de
   evaluacion, sesiones, hallazgos, informes, webhooks, CSV) esta en GitHub y en
   la release `v3.5.0`, pero no se ha podido subir a PyPI porque el publisher OIDC
   del repo no esta registrado en PyPI (`invalid-publisher`). Si instalas desde
   PyPI hoy, **no** tienes la consola de evaluacion.
3. **Docker:** `docker compose up` (demo con sesion cerrada).
   **No verificado**: los ficheros `Dockerfile` y `docker-compose.yml` existen y
   la demo local (`m5wireless demo`) si funciona, pero nadie ha ejecutado el
   contenedor. Considera la imagen como "sin probar" hasta que se ejecute.

Requisitos: Python 3.11 o 3.12. Serial: `pyserial` (opcional, solo para
`--source serial`).
