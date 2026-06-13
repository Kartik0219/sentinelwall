---
title: SentinelWall
emoji: 🛡️
colorFrom: red
colorTo: gray
sdk: docker
app_port: 8000
pinned: false
---

<!-- The YAML block above configures the Hugging Face Space deployment (Docker SDK,
     port 8000). GitHub renders it as a small metadata table; it is harmless there. -->

# SentinelWall

A hybrid-cloud incident response & containment agent — a small Cloud SOAR (Security
Orchestration, Automation, and Response) utility that ingests Microsoft Defender for
Cloud / Azure Monitor style alerts, scores them against a local risk matrix, and
automatically contains malicious external IPs at the network edge (`ufw` / `iptables`).

## Architecture

```
                 ┌────────────────────────┐
  Azure Monitor  │   FastAPI Ingestion    │      ┌──────────────┐
  / Defender for │   POST /api/v1/alerts/ │      │  asyncio.    │
  Cloud webhook ─┼─▶ azure  (token/HMAC   ┼─────▶│  Queue       │
                 │   verified, Pydantic   │      │  (buffer)    │
                 │   validated)           │      └──────┬───────┘
                 └────────────────────────┘             │
                                                         ▼
                 ┌────────────────────────────────────────────────┐
                 │  Mitigation Worker (background asyncio task)    │
                 │   • RulesEngine.evaluate() — alert_policies.yaml│
                 │   • asyncio.Lock guards check-then-act sequence │
                 │   • persists IngestedAlert + ContainmentBlock   │
                 └───────────────┬─────────────────────┬──────────┘
                                 │                      │
                                 ▼                      ▼
                    ┌────────────────────┐   ┌────────────────────────┐
                    │  SQLite (SQLAlchemy│   │  BaseFirewallDriver     │
                    │  async, aiosqlite) │   │   • UFWFirewallDriver   │
                    │   alerts / blocks  │   │   • IPTablesFirewall... │
                    └────────────────────┘   │   • MockFirewallDriver  │
                                 ▲            └────────────────────────┘
                                 │
                    ┌────────────┴───────────┐
                    │  Expiry Scanner (30s)  │── unblocks IPs whose TTL elapsed
                    └────────────────────────┘

                 ┌────────────────────────┐
                 │  SOC Dashboard (static │◀── polls /api/v1/dashboard/* every 5s
                 │  HTML/JS + Tailwind)   │
                 └────────────────────────┘
```

## Layers

1. **Cloud Ingestion Layer** — `app/routers/alerts.py`: an async FastAPI webhook that
   verifies a shared-secret `X-Webhook-Token` header (constant-time comparison via
   `hmac.compare_digest`) before accepting and Pydantic-validating the payload, then
   drops it onto an `asyncio.Queue` so ingestion never blocks on processing.
2. **Decision Engine** — `app/engine/rules.py` + `app/engine/worker.py`: a YAML-driven
   risk-matrix (`alert_policies.yaml`) scores each alert; a background worker drains the
   queue sequentially and an `asyncio.Lock` serializes the check-then-block sequence so
   duplicate concurrent alerts for the same IP never trigger duplicate firewall calls.
3. **Containment Layer** — `app/firewall/`: a `BaseFirewallDriver` ABC with `ufw`,
   `iptables`, and `mock` implementations. All commands run via
   `asyncio.create_subprocess_exec` with `shell=False` and strict argv arrays — no
   string ever reaches a shell, eliminating command injection.

## Running locally

```bash
python -m venv .venv
source .venv/bin/activate        # .venv\Scripts\activate on Windows
pip install -r requirements.txt

cp .env.example .env             # then edit SENTINELWALL_WEBHOOK_TOKEN
export $(cat .env | xargs)       # or set the vars manually on Windows

uvicorn app.main:app --reload
```

Open http://localhost:8000/ for the SOC dashboard.

### Sending a test alert

```bash
curl -X POST http://localhost:8000/api/v1/alerts/azure \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: <your SENTINELWALL_WEBHOOK_TOKEN>" \
  -d '{
        "subscriptionId": "sub-1234",
        "resourceGroup": "rg-prod-eastus",
        "alertName": "Brute Force SSH Attack",
        "severity": "High",
        "extendingProperties": {"compromised_ip": "203.0.113.50"}
      }'
```

## Configuration

| Env var                          | Purpose                                              | Default               |
|----------------------------------|------------------------------------------------------|-----------------------|
| `SENTINELWALL_WEBHOOK_TOKEN`     | Shared secret required in `X-Webhook-Token` header  | *(required)*          |
| `SENTINELWALL_DB_PATH`           | Path to the SQLite state database                    | `sentinelwall.db`     |
| `SENTINELWALL_FIREWALL_DRIVER`   | `mock` \| `ufw` \| `iptables`                        | `mock`                |
| `SENTINELWALL_POLICIES_PATH`     | Path to the YAML risk-matrix rules file              | `alert_policies.yaml` |

Edit `alert_policies.yaml` to tune which alert names / severities trigger `BLOCK_IP`
and for how long (`ttl_seconds`).

## Running with Docker

```bash
echo "SENTINELWALL_WEBHOOK_TOKEN=$(openssl rand -hex 32)" > .env
docker compose up --build
```

The container ships with the `mock` firewall driver by default (safe, no host
privileges needed). To perform real containment on a Linux host, run the process
directly (not in a container, unless you grant `--cap-add=NET_ADMIN` and mount the
host's `/etc` appropriately) with `SENTINELWALL_FIREWALL_DRIVER=ufw` or `iptables`,
and ensure the running user has passwordless `sudo` for that specific binary.

## Tests

```bash
pytest -q
```

The suite mocks the OS-level firewall driver entirely (`MockFirewallDriver` and
monkeypatched `run_command`), so it runs cleanly in CI/GitHub Actions without root.

## Security notes

- Webhook auth uses constant-time token comparison (`hmac.compare_digest`) to resist
  timing attacks; requests without a configured token are rejected with `503`.
- All inbound fields are validated with Pydantic v2 (IPv4 format, length limits,
  control-character rejection) before they ever reach business logic.
- Firewall commands are invoked as argv arrays via `asyncio.create_subprocess_exec`
  with `shell=False` — never through a shell string — and the IP is re-validated
  immediately before use as defense in depth against injection.
- Firewall failures are caught, logged as structured JSON, and trip a `Degraded`
  system status surfaced on the dashboard — the API and ingestion queue stay up.
