"""Structured JSON logging with a correlation ID bound per scan_run.

Every log line during a scan carries `scan_run_id` so a triage decision made at
2am can be traced back to the run that produced it six months later.
"""

from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import structlog


def configure_logging(*, level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(**initial_context: object) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(**initial_context)  # type: ignore[no-any-return]


@contextmanager
def scan_run_context(scan_run_id: uuid.UUID | None = None) -> Iterator[uuid.UUID]:
    """Bind `scan_run_id` to every log line emitted within this context."""
    run_id = scan_run_id or uuid.uuid4()
    structlog.contextvars.bind_contextvars(scan_run_id=str(run_id))
    try:
        yield run_id
    finally:
        structlog.contextvars.unbind_contextvars("scan_run_id")
