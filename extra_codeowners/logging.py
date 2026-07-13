"""Structured logging configuration with secret-safe defaults."""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(level: str, *, json_logs: bool) -> None:
    """Configure stdlib and structlog for either development or production."""
    logging.basicConfig(format="%(message)s", level=level, stream=sys.stdout, force=True)
    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]
    if json_logs:
        processors.append(structlog.processors.format_exc_info)
    processors.append(
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
