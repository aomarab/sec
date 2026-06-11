FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Reports persist here; mount a volume to keep them on the host
RUN mkdir -p /app/reports
ENV REPORTS_DIR=/app/reports

# Run as non-root
RUN useradd --create-home --uid 10001 agent && chown -R agent:agent /app
USER agent

ENTRYPOINT ["python", "main.py"]
