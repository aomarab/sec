FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System packages:
#  - nmap: optional advanced network-scan features (service/version, vuln scripts)
#  - build tools + cairo/ffi headers: needed to compile pycairo (a PDF-export
#    dependency that has no prebuilt wheel on this image).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        gcc g++ make pkg-config python3-dev \
        libcairo2-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# All mutable state lives under /app/data so it can be persisted with one volume.
ENV DATA_DIR=/app/data \
    REPORTS_DIR=/app/data/reports \
    UPLOADS_DIR=/app/data/uploads \
    BRANDING_DIR=/app/data/branding \
    USERS_FILE=/app/data/users.json \
    FLASK_SECRET_FILE=/app/data/.flask_secret \
    SCHEDULE_FILE=/app/data/schedule.json \
    SCAN_SCHED_FILE=/app/data/scan_schedule.json \
    SCAN_STATS_FILE=/app/data/scan_stats.json \
    ASSETS_FILE=/app/data/assets.json \
    ALERTS_FILE=/app/data/alerts.json \
    OWNERS_FILE=/app/data/report_owners.json \
    API_KEYS_FILE=/app/data/api_keys.json \
    WEB_PORT=5000

RUN mkdir -p /app/data/reports /app/data/uploads /app/data/branding

EXPOSE 5000

# Runs as root for reliable writes to a bind-mounted ./data volume across
# platforms. For a hardened deployment, add a non-root user and a named volume.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5000/login',timeout=4).status==200 else 1)"

CMD ["python", "webapp.py"]
