"""Shared pytest fixtures: isolated DB per test, mocked firewall, async test client."""
import asyncio
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Force (not setdefault) test-only values: the fixture below deletes the configured DB
# file on setup/teardown, so it must never be allowed to inherit a developer's real
# SENTINELWALL_DB_PATH or a non-mock SENTINELWALL_FIREWALL_DRIVER from their shell env.
os.environ["SENTINELWALL_WEBHOOK_TOKEN"] = "test-secret-token"
os.environ["SENTINELWALL_DB_PATH"] = "test_sentinelwall.db"
os.environ["SENTINELWALL_FIREWALL_DRIVER"] = "mock"


@pytest_asyncio.fixture
async def app_with_state():
    # Imported lazily so the env vars above are in place before app.config reads them.
    from app.db.session import dispose_engine, init_db
    from app.engine.rules import RulesEngine
    from app.engine.worker import expiry_scanner, mitigation_worker
    from app.firewall.mock_driver import MockFirewallDriver
    from app.main import create_app
    from app.state import AppState

    db_path = os.environ["SENTINELWALL_DB_PATH"]
    if os.path.exists(db_path):
        os.remove(db_path)

    await init_db()

    state = AppState(
        alert_queue=asyncio.Queue(maxsize=100),
        rules_engine=RulesEngine.from_yaml_file("alert_policies.yaml"),
        firewall=MockFirewallDriver(),
    )

    app = create_app()
    app.state.sentinel = state

    worker_task = asyncio.create_task(mitigation_worker(state))
    scanner_task = asyncio.create_task(expiry_scanner(state, interval_seconds=3600))

    try:
        yield app, state
    finally:
        worker_task.cancel()
        scanner_task.cancel()
        await asyncio.gather(worker_task, scanner_task, return_exceptions=True)
        await dispose_engine()
        if os.path.exists(os.environ["SENTINELWALL_DB_PATH"]):
            os.remove(os.environ["SENTINELWALL_DB_PATH"])


@pytest_asyncio.fixture
async def client(app_with_state):
    app, _state = app_with_state
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def auth_headers():
    return {"X-Webhook-Token": os.environ["SENTINELWALL_WEBHOOK_TOKEN"]}
