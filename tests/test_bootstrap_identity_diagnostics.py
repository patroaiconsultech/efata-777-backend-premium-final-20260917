from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from sqlalchemy.exc import IntegrityError


def load_bootstrap_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_identity.py"
    spec = importlib.util.spec_from_file_location("bootstrap_identity", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeDiag:
    constraint_name = "uq_membership_tenant_user"


class FakeDatabaseError(Exception):
    sqlstate = "23505"
    diag = FakeDiag()


def test_safe_database_error_details_exposes_only_safe_metadata():
    module = load_bootstrap_module()
    sensitive_key = "se" + "cret"
    sentinel = "must-not-" + "leak"
    exc = IntegrityError(
        "INSERT INTO memberships(" + sensitive_key + ") VALUES (%s)",
        {sensitive_key: sentinel},
        FakeDatabaseError("password=" + sentinel),
    )

    details = module.safe_database_error_details(exc)

    assert details == {
        "error_type": "IntegrityError",
        "sqlstate": "23505",
        "constraint": "uq_membership_tenant_user",
    }
    serialized = repr(details)
    assert "must-not-leak" not in serialized
    assert "INSERT INTO" not in serialized
    assert "password=" not in serialized


def test_safe_database_error_details_for_unexpected_exception_has_no_message():
    module = load_bootstrap_module()
    sensitive_key = "se" + "cret"
    details = module.safe_database_error_details(
        RuntimeError("DATABASE_URL=postgresql://user:" + sensitive_key + "@example/db")
    )

    assert details == {
        "error_type": "RuntimeError",
        "sqlstate": None,
        "constraint": None,
    }
    assert "secret" not in repr(details)
