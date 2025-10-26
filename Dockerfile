# syntax=docker/dockerfile:1

FROM node:20-alpine AS web_builder
WORKDIR /webui
COPY webui/package*.json ./
RUN npm ci
COPY webui/ ./
RUN npm run build

FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/app/data
WORKDIR /app

COPY bot/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY bot/ ./bot/
COPY --from=web_builder /webui/dist ./webui/dist

RUN mkdir -p /app/data

EXPOSE 8447

CMD ["python", "-u", "bot/main.py"]
