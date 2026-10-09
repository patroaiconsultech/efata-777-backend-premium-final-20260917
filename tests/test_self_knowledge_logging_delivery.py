from __future__ import annotations

import io
import logging
import sys
from unittest.mock import patch

import pytest

from orkio_v2.self_knowledge_logging import configure_self_knowledge_logging

NAME = "orkio.self_knowledge"


@pytest.fixture
def isolated_logging():
    child = logging.getLogger(NAME)
    parent = logging.getLogger("orkio")
    root = logging.getLogger()
    tracked = [child, parent, root, logging.getLogger("uvicorn.error")]
    saved = [(x.level, x.disabled, x.propagate, x.handlers[:]) for x in tracked]
    try:
        child.handlers = []
        parent.handlers = []
        root.handlers = []
        child.setLevel(logging.NOTSET)
        child.disabled = False
        child.propagate = True
        parent.setLevel(logging.NOTSET)
        parent.propagate = True
        root.setLevel(logging.WARNING)
        yield child, root
    finally:
        for logger, (level, disabled, propagate, handlers) in zip(tracked, saved):
            for handler in logger.handlers:
                if handler not in handlers and getattr(handler, "_efata_self_knowledge_stderr", False):
                    handler.close()
            logger.handlers = handlers
            logger.setLevel(level)
            logger.disabled = disabled
            logger.propagate = propagate


def test_root_warning_no_console_adds_stderr_and_propagates(isolated_logging):
    child, root = isolated_logging
    capture = io.StringIO()
    observer = logging.StreamHandler(io.StringIO())
    observer.setLevel(logging.INFO)
    root.addHandler(observer)
    with patch.object(sys, "stderr", capture):
        configure_self_knowledge_logging()
        configure_self_knowledge_logging()
        child.info("self_knowledge.github_selection id=one")
    assert capture.getvalue().count("self_knowledge.github_selection") == 1
    assert child.propagate is True
    assert child.getEffectiveLevel() == logging.INFO
    assert "self_knowledge.github_selection" in observer.stream.getvalue()


def test_root_info_console_prevents_duplicate(isolated_logging):
    child, root = isolated_logging
    output = io.StringIO()
    with patch.object(sys, "stderr", output):
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.INFO)
        root.addHandler(handler)
        configure_self_knowledge_logging()
        configure_self_knowledge_logging()
        child.info("unique-root-info")
    assert output.getvalue().count("unique-root-info") == 1
    assert len(child.handlers) == 0


def test_root_warning_handler_warning_needs_stderr_fallback(isolated_logging):
    child, root = isolated_logging
    output = io.StringIO()
    with patch.object(sys, "stderr", output):
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.WARNING)
        root.addHandler(handler)
        configure_self_knowledge_logging()
        child.info("fallback-root-warning")
    assert output.getvalue().count("fallback-root-warning") == 1
    assert len(child.handlers) == 1


def test_preexisting_child_stderr_handler_reused(isolated_logging):
    child, root = isolated_logging
    output = io.StringIO()
    with patch.object(sys, "stderr", output):
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.INFO)
        child.addHandler(handler)
        configure_self_knowledge_logging()
        child.info("preexisting-child")
    assert output.getvalue().count("preexisting-child") == 1
    assert child.handlers == [handler]


def test_caplog_receives_info_while_fallback_delivers_stderr(caplog):
    child = logging.getLogger(NAME)
    saved = (child.level, child.disabled, child.propagate, child.handlers[:])
    try:
        child.handlers = []
        caplog.set_level(logging.INFO, logger=NAME)
        configure_self_knowledge_logging()
        child.info("self_knowledge.caplog_probe")
        assert "self_knowledge.caplog_probe" in caplog.text
        assert child.propagate is True
    finally:
        for handler in child.handlers:
            if handler not in saved[3] and getattr(handler, "_efata_self_knowledge_stderr", False):
                child.removeHandler(handler)
                handler.close()
        child.handlers = saved[3]
        child.setLevel(saved[0])
        child.disabled = saved[1]
        child.propagate = saved[2]


def test_does_not_change_root_or_uvicorn(isolated_logging):
    child, root = isolated_logging
    uvicorn = logging.getLogger("uvicorn.error")
    before = (root.level, root.handlers[:], uvicorn.level, uvicorn.handlers[:])
    configure_self_knowledge_logging()
    assert (root.level, root.handlers[:], uvicorn.level, uvicorn.handlers[:]) == before
