
from __future__ import annotations

import pytest

from orkio_v2.services.audit_invocation_directive import (
    AuditDirectiveError,
    looks_like_audit_directive,
    parse_audit_directive,
)


def test_plain_language_never_invokes():
    assert looks_like_audit_directive("Natã, audite este arquivo") is False
    assert parse_audit_directive("Natã, audite este arquivo") is None


def test_exact_runtime_directive_parses_one_operation():
    directive = parse_audit_directive(
        '/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}'
    )
    assert directive is not None
    assert directive.operation == "runtime.file_sha256"
    assert directive.spec.capability_id == "audit.runtime.file_sha256@1.0.0"
    assert directive.arguments == {"module_id": "routes"}


@pytest.mark.parametrize(
    "message,code",
    [
        ('/audit{"version":"1","operation":"runtime.file_sha256","module_id":"routes"}', "AUDIT_DIRECTIVE_FORMAT_INVALID"),
        (' /audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"}', "AUDIT_DIRECTIVE_FORMAT_INVALID"),
        ('/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes"} trailing', "AUDIT_DIRECTIVE_TRAILING_TEXT_FORBIDDEN"),
        ('/audit []', "AUDIT_DIRECTIVE_OBJECT_REQUIRED"),
        ('/audit {"version":"2","operation":"runtime.file_sha256","module_id":"routes"}', "AUDIT_DIRECTIVE_VERSION_INVALID"),
        ('/audit {"version":"1","operation":"runtime.nope","module_id":"routes"}', "AUDIT_OPERATION_UNKNOWN"),
        ('/audit {"version":"1","operation":"runtime.file_sha256"}', "AUDIT_DIRECTIVE_REQUIRED_FIELD_MISSING"),
        ('/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes","extra":1}', "AUDIT_DIRECTIVE_UNKNOWN_FIELD"),
        ('/audit {"version":"1","operation":"file.metadata","artifact_id":"a","tenant_id":"tenant-2"}', "AUDIT_DIRECTIVE_FORBIDDEN_FIELD"),
        ('/audit {"version":"1","operation":"file.metadata","artifact_id":"a","relative_path":"../../x"}', "AUDIT_DIRECTIVE_FORBIDDEN_FIELD"),
        ('/audit {"version":"1","operation":"runtime.file_sha256","module_id":"routes","sql":"select 1"}', "AUDIT_DIRECTIVE_FORBIDDEN_FIELD"),
        ('/audit {"version":"1","operation":"file.read_text","artifact_id":"a","offset":true}', "AUDIT_DIRECTIVE_FIELD_INVALID"),
    ],
)
def test_directive_negative_matrix(message, code):
    with pytest.raises(AuditDirectiveError) as exc:
        parse_audit_directive(message)
    assert exc.value.code == code
