FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EXPORTER_PORT=8001

WORKDIR /app

RUN addgroup --system exporter \
    && adduser --system --ingroup exporter exporter

COPY exporter/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY exporter/ /app/exporter/

RUN mkdir -p /app/exporter/logs \
    && chown -R exporter:exporter /app

USER exporter
WORKDIR /app/exporter

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.getenv('EXPORTER_PORT', '8001'), timeout=3).read()"

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${EXPORTER_PORT:-8001} --workers ${GUNICORN_WORKERS:-1} --timeout ${GUNICORN_TIMEOUT:-120} veeam_exporter:application"]
