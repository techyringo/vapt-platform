FROM golang:1.25-bookworm AS go-tools

ENV GOBIN=/out
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/httprobe@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/OJ/gobuster/v3@v3.7.0 && \
    go install github.com/tomnomnom/qsreplace@latest

FROM python:3.12-slim

WORKDIR /app

# System deps: nmap (used directly + by enum agent), curl, git, dnsutils
# (dig for cloud agent), plus build deps for lxml. Docker CLI is installed
# from the official static bundle so socket-mounted tool isolation does not
# depend on Debian's package availability.
ARG DOCKER_CLI_VERSION=27.5.1
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git dnsutils ca-certificates tar \
    libxml2 libxslt1.1 \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
      amd64) docker_arch="x86_64" ;; \
      arm64) docker_arch="aarch64" ;; \
      armhf) docker_arch="armhf" ;; \
      *) echo "Unsupported Docker CLI architecture: $arch" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${docker_arch}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && chmod +x /usr/local/bin/docker \
    && docker --version \
    && rm -rf /tmp/docker /tmp/docker.tgz /var/lib/apt/lists/*

COPY --from=go-tools /out/waybackurls /usr/local/bin/waybackurls
COPY --from=go-tools /out/subfinder /usr/local/bin/subfinder
COPY --from=go-tools /out/httpx /usr/local/bin/httpx
COPY --from=go-tools /out/nuclei /usr/local/bin/nuclei
COPY --from=go-tools /out/katana /usr/local/bin/katana
COPY --from=go-tools /out/dnsx /usr/local/bin/dnsx
COPY --from=go-tools /out/naabu /usr/local/bin/naabu
COPY --from=go-tools /out/tlsx /usr/local/bin/tlsx
COPY --from=go-tools /out/ffuf /usr/local/bin/ffuf
COPY --from=go-tools /out/puredns /usr/local/bin/puredns
COPY --from=go-tools /out/assetfinder /usr/local/bin/assetfinder
COPY --from=go-tools /out/httprobe /usr/local/bin/httprobe
COPY --from=go-tools /out/gau /usr/local/bin/gau
COPY --from=go-tools /out/hakrawler /usr/local/bin/hakrawler
COPY --from=go-tools /out/gobuster /usr/local/bin/gobuster
COPY --from=go-tools /out/qsreplace /usr/local/bin/qsreplace

# Nuclei needs templates available at runtime. The upstream Docker image does
# not guarantee a template corpus, so we use the local binary and bake the
# default template set into the backend/worker image.
ENV NUCLEI_TEMPLATES_DIRECTORY=/nuclei-templates
RUN mkdir -p /nuclei-templates /root/nuclei-templates && \
    (git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git /tmp/nuclei-templates \
      && cp -a /tmp/nuclei-templates/. /nuclei-templates/ \
      && rm -rf /tmp/nuclei-templates) \
    || nuclei -update-templates -silent \
    || nuclei -ut -silent \
    || true && \
    if [ -d /root/nuclei-templates ] && [ -z "$(ls -A /nuclei-templates 2>/dev/null)" ]; then \
      cp -a /root/nuclei-templates/. /nuclei-templates/ || true; \
    fi && \
    find /nuclei-templates -type f \( -name '*.yaml' -o -name '*.yml' \) | head -n 1 | grep -q .

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir arjun wafw00f

# App code
COPY . .

# Shared temp dir for Docker-tool input files plus durable SQLite/artifact state.
RUN mkdir -p /tmp/vapt-shared /app/data /app/artifacts && chmod 777 /tmp/vapt-shared /app/data /app/artifacts

EXPOSE 8443

# NOTE: correct uvicorn factory syntax is `module:create_app --factory`
# (NOT `module:create_app:app --factory` — that import string is malformed)
CMD ["python", "-m", "uvicorn", "web.app:create_app", \
     "--host", "0.0.0.0", "--port", "8443", "--factory", \
     "--log-level", "info", "--no-access-log"]
