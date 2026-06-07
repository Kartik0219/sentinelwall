"""Cloud webhook ingestion router: authenticated POST endpoint that enqueues alerts."""
import hmac
import logging

from fastapi import APIRouter, Header, HTTPException, Request, status

from app.config import settings
from app.schemas import AlertIngestResponse, AzureAlert
from app.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


def _verify_token(provided: str | None) -> None:
    """Constant-time comparison of the shared-secret webhook token to prevent timing attacks."""
    if not settings.webhook_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="webhook authentication is not configured on this server",
        )
    if provided is None or not hmac.compare_digest(provided, settings.webhook_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing webhook token")


@router.post("/azure", response_model=AlertIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_azure_alert(
    alert: AzureAlert,
    request: Request,
    x_webhook_token: str | None = Header(default=None, alias="X-Webhook-Token"),
) -> AlertIngestResponse:
    _verify_token(x_webhook_token)

    state: AppState = request.app.state.sentinel
    await state.alert_queue.put(alert)

    logger.info(
        "alert accepted into ingestion queue",
        extra={
            "component": "router.alerts",
            "action": "ingest",
            "status": "queued",
            "target_ip": alert.extendingProperties.compromised_ip,
        },
    )

    return AlertIngestResponse(
        queued=True,
        message="alert accepted and queued for evaluation",
    )
