FROM python:3.12-slim

WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Command is set per-service in docker-compose.yml — this image serves
# both the HTTP app (uvicorn app.main:app) and the standalone TCP MySQL
# handshake decoy (python -m app.services.db_handshake).
