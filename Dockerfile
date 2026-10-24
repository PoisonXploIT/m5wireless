FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir ".[web]"

# La demo escribe aqui; se puede montar con docker compose (volumen ./data).
ENV M5W_DB_PATH=/app/data/demo.db
ENV M5W_UI_TOKEN=${M5W_UI_TOKEN}

EXPOSE 8000

# Arranca con una sesion ya cerrada: fixture sintetico -> 5 hallazgos -> informe.
CMD ["m5wireless", "demo", "--serve", "--host", "0.0.0.0", "--port", "8000"]
