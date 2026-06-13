"""SentinelWall FastAPI application entry point: wiring, lifespan, and router registration."""
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import demo
from app.config import settings
from app.db.session import dispose_engine, init_db
from app.engine.rules import RulesEngine
from app.engine.worker import expiry_scanner, mitigation_worker
from app.firewall.factory import build_firewall_driver
from app.logging_setup import configure_logging
from app.routers import alerts, dashboard
from app.state import AppState

configure_logging(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    state = AppState(
        alert_queue=asyncio.Queue(maxsize=1000),
        rules_engine=RulesEngine.from_yaml_file(settings.policies_path),
        firewall=build_firewall_driver(settings.firewall_driver),
    )
    app.state.sentinel = state

    worker_task = asyncio.create_task(mitigation_worker(state))
    scanner_task = asyncio.create_task(expiry_scanner(state, settings.expiry_scan_interval_seconds))

    if settings.demo_mode:
        await demo.seed(state)

    logger.info(
        "SentinelWall started",
        extra={"component": "main", "action": "startup", "status": "success", "target_ip": "-"},
    )
    try:
        yield
    finally:
        for task in (worker_task, scanner_task):
            task.cancel()
        await asyncio.gather(worker_task, scanner_task, return_exceptions=True)
        await dispose_engine()
        logger.info(
            "SentinelWall stopped",
            extra={"component": "main", "action": "shutdown", "status": "success", "target_ip": "-"},
        )


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelWall",
        description="Hybrid-Cloud Incident Response & Containment Agent",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.include_router(alerts.router)
    app.include_router(dashboard.router)
    app.include_router(demo.router)
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
    return app


app = create_app()
