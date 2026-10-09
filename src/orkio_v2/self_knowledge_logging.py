"""Targeted delivery for metadata-only self-knowledge diagnostics.

Preserves logging propagation for parent observers and pytest caplog.
Does not change root/Uvicorn configuration.
"""
from __future__ import annotations

import logging
import sys

_LOGGER_NAME = "orkio.self_knowledge"
_HANDLER_MARKER = "_efata_self_knowledge_stderr"


def _has_console_info_delivery(logger: logging.Logger) -> bool:
    """Find a reachable console handler that accepts INFO records."""
    current: logging.Logger | None = logger
    while current is not None:
        for handler in current.handlers:
            if getattr(handler, _HANDLER_MARKER, False):
                continue
            if (
                isinstance(handler, logging.StreamHandler)
                and not isinstance(handler, logging.FileHandler)
                and handler.level <= logging.INFO
                and handler.stream in (sys.stdout, sys.stderr)
                and not handler.filters
            ):
                return True
        if not current.propagate:
            break
        current = current.parent
    return False


def configure_self_knowledge_logging() -> None:
    """Ensure INFO reaches console while preserving parent logging observers.

    Idempotent for the R4.1-owned handler. Existing non-console handlers,
    including caplog, remain usable through propagation.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.disabled = False
    logger.propagate = True

    owned = [h for h in logger.handlers if getattr(h, _HANDLER_MARKER, False)]
    if _has_console_info_delivery(logger):
        for handler in owned:
            logger.removeHandler(handler)
            handler.close()
        return

    if owned:
        handler = owned[0]
        for duplicate in owned[1:]:
            logger.removeHandler(duplicate)
            duplicate.close()
        handler.setLevel(logging.INFO)
        return

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    setattr(handler, _HANDLER_MARKER, True)
    logger.addHandler(handler)
