"""Structured JSON logging configuration for SIEM-friendly output."""
import logging
import sys

try:
    from pythonjsonlogger import json as jsonlogger  # python-json-logger >= 3.x
except ImportError:  # pragma: no cover - fallback for python-json-logger < 3.x
    from pythonjsonlogger import jsonlogger

_FIELDS = "%(asctime)s %(levelname)s %(name)s %(component)s %(action)s %(status)s %(target_ip)s %(message)s"


class _DefaultFieldFilter(logging.Filter):
    """Ensures optional structured fields always exist so the JSON formatter never KeyErrors."""

    def filter(self, record: logging.LogRecord) -> bool:
        for field in ("component", "action", "status", "target_ip"):
            if not hasattr(record, field):
                setattr(record, field, "-")
        return True


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(jsonlogger.JsonFormatter(_FIELDS))
    handler.addFilter(_DefaultFieldFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
