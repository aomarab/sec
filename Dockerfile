FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Core system packages (required — these are present in the base image's repos):
#  - nmap: advanced network-scan features (service/version, vuln scripts)
#  - masscan: fast port discovery; testssl.sh: TLS configuration assessment
#  - dnsutils: testssl.sh runtime helper; curl/unzip/tar: fetch release binaries
#  - build tools + cairo/ffi headers: needed to compile pycairo (PDF export).
#  Detection/recon tooling only — no exploitation/brute-force packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap masscan testssl.sh \
        ca-certificates curl unzip dnsutils tar git perl libnet-ssleay-perl \
        gcc g++ make pkg-config python3-dev \
        libcairo2-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Detection tools that may not be in every base repo — best-effort, never fatal.
# sqlmap (apt if available, else pip); nikto via upstream Perl source.
RUN (apt-get update && apt-get install -y --no-install-recommends sqlmap && rm -rf /var/lib/apt/lists/*) \
      || pip install --no-cache-dir sqlmap \
      || echo "WARNING: sqlmap install skipped."
RUN (git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
       && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
       && chmod +x /opt/nikto/program/nikto.pl \
       && nikto -Version) \
      || echo "WARNING: nikto install skipped."

# Go-binary tools from upstream releases (pinned). Each step is best-effort:
# the build continues if a download is unavailable and the app degrades gracefully.
ARG TARGETARCH=amd64
ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.6
ARG FFUF_VERSION=2.1.0
ARG AMASS_VERSION=4.2.0
ARG HTTPX_VERSION=1.6.9
ARG DNSX_VERSION=1.2.1
ARG GAU_VERSION=2.2.4
RUN set -eux; \
    (curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/n.zip \
       && unzip -o /tmp/n.zip nuclei -d /usr/local/bin && chmod +x /usr/local/bin/nuclei && nuclei -version) \
       || echo "WARNING: nuclei install skipped."; \
    (curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/s.zip \
       && unzip -o /tmp/s.zip subfinder -d /usr/local/bin && chmod +x /usr/local/bin/subfinder && subfinder -version) \
       || echo "WARNING: subfinder install skipped."; \
    (curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${TARGETARCH}.tar.gz" -o /tmp/f.tgz \
       && tar -xzf /tmp/f.tgz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf && ffuf -V) \
       || echo "WARNING: ffuf install skipped."; \
    (curl -fsSL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${TARGETARCH}.zip" -o /tmp/a.zip \
       && unzip -o /tmp/a.zip -d /tmp/amass \
       && cp /tmp/amass/amass_Linux_${TARGETARCH}/amass /usr/local/bin/amass && chmod +x /usr/local/bin/amass && amass -version) \
       || echo "WARNING: amass install skipped."; \
    (curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/h.zip \
       && unzip -o /tmp/h.zip httpx -d /usr/local/bin && chmod +x /usr/local/bin/httpx && httpx -version) \
       || echo "WARNING: httpx install skipped."; \
    (curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/d.zip \
       && unzip -o /tmp/d.zip dnsx -d /usr/local/bin && chmod +x /usr/local/bin/dnsx && dnsx -version) \
       || echo "WARNING: dnsx install skipped."; \
    (curl -fsSL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${TARGETARCH}.tar.gz" -o /tmp/g.tgz \
       && tar -xzf /tmp/g.tgz -C /usr/local/bin gau && chmod +x /usr/local/bin/gau && gau --version) \
       || echo "WARNING: gau install skipped."; \
    rm -rf /tmp/n.zip /tmp/s.zip /tmp/f.tgz /tmp/a.zip /tmp/amass /tmp/h.zip /tmp/d.zip /tmp/g.tgz

# Python-based scanners (Wapiti, Droopescan) — best-effort.
RUN pip install --no-cache-dir wapiti3 droopescan || echo "WARNING: wapiti/droopescan install skipped."

# Trivy (deps/containers/IaC) and gitleaks (repo secrets) — release binaries, best-effort.
ARG TRIVY_VERSION=0.55.2
ARG GITLEAKS_VERSION=8.21.2
RUN set -eux; \
    (curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/t.tgz \
       && tar -xzf /tmp/t.tgz -C /usr/local/bin trivy && chmod +x /usr/local/bin/trivy && trivy --version) \
       || echo "WARNING: trivy install skipped."; \
    (curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gl.tgz \
       && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks && gitleaks version) \
       || echo "WARNING: gitleaks install skipped."; \
    rm -f /tmp/t.tgz /tmp/gl.tgz

# retire.js (vulnerable front-end JS) — needs Node; best-effort.
RUN (apt-get update && apt-get install -y --no-install-recommends nodejs npm \
       && npm install -g retire \
       && retire --version \
       && rm -rf /var/lib/apt/lists/*) \
     || echo "WARNING: retire.js install skipped (Node unavailable)."

# WPScan (Ruby gem) — best-effort; needs a Ruby toolchain. The app degrades
# gracefully (the WordPress option just shows "not detected") if this is skipped.
RUN (apt-get update \
       && apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev zlib1g-dev \
       && gem install wpscan --no-document \
       && wpscan --version \
       && rm -rf /var/lib/apt/lists/*) \
     || echo "WARNING: wpscan install skipped (Ruby toolchain unavailable)."

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
    RECON_SCHED_FILE=/app/data/recon_schedule.json \
    SCAN_STATS_FILE=/app/data/scan_stats.json \
    ASSETS_FILE=/app/data/assets.json \
    ALERTS_FILE=/app/data/alerts.json \
    OWNERS_FILE=/app/data/report_owners.json \
    API_KEYS_FILE=/app/data/api_keys.json \
    AUDIT_LOG_FILE=/app/data/audit_log.jsonl \
    MONITOR_FILE=/app/data/monitor_snapshots.json \
    FINDINGS_FILE=/app/data/findings.json \
    WEB_PORT=5000

RUN mkdir -p /app/data/reports /app/data/uploads /app/data/branding

EXPOSE 5000

# Runs as root for reliable writes to a bind-mounted ./data volume across
# platforms. For a hardened deployment, add a non-root user and a named volume.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5000/login',timeout=4).status==200 else 1)"

CMD ["python", "webapp.py"]
