# --- Stage 1: build dependencies in an isolated layer ---
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: minimal runtime image ---
FROM python:3.12-slim AS runtime

# ufw/iptables are optional host tools the real drivers shell out to; the default
# "mock" driver needs neither, so the runtime image stays slim unless overridden.
RUN useradd --create-home --shell /usr/sbin/nologin sentinel

COPY --from=builder /install /usr/local

WORKDIR /app
COPY app ./app
COPY alert_policies.yaml .

ENV SENTINELWALL_DB_PATH=/data/sentinelwall.db \
    SENTINELWALL_FIREWALL_DRIVER=mock \
    SENTINELWALL_POLICIES_PATH=/app/alert_policies.yaml

RUN mkdir -p /data && chown -R sentinel:sentinel /app /data
USER sentinel

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
