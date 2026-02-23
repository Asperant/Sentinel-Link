FROM python:3.10-slim

RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir redis psycopg2-binary cryptography