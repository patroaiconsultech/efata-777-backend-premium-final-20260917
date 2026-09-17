import pytest

from tools.efata_schema_collector.function_fingerprint import (
    FunctionConfigCanonicalizationError,
    UnsupportedSecurityFunctionLanguage,
    canonicalize_proconfig,
    fingerprint_security_sensitive_function,
)


def row(**updates):
    base = {
        "schema_name": "public",
        "function_name": "f",
        "identity_arguments": "integer",
        "language": "plpgsql",
        "prokind": "f",
        "prosecdef": True,
        "proleakproof": False,
        "proisstrict": False,
        "provolatile": "v",
        "proparallel": "u",
        "proconfig": ["search_path=pg_catalog, public", "work_mem=4MB"],
        "prosrc": "BEGIN RETURN $1; END",
        "probin": None,
        "has_prosqlbody": False,
        "function_definition": "CREATE FUNCTION public.f(integer) RETURNS integer LANGUAGE plpgsql AS $$BEGIN RETURN $1; END$$",
    }
    base.update(updates)
    return base


def test_proconfig_order_is_canonical():
    a = canonicalize_proconfig(["work_mem=4MB", "search_path=pg_catalog"])
    b = canonicalize_proconfig(["search_path=pg_catalog", "work_mem=4MB"])
    assert a == b


def test_duplicate_proconfig_key_fails():
    with pytest.raises(FunctionConfigCanonicalizationError):
        canonicalize_proconfig(["search_path=a", "SEARCH_PATH=b"])


def test_body_mutation_changes_fingerprint():
    a, _ = fingerprint_security_sensitive_function(row())
    b, _ = fingerprint_security_sensitive_function(row(prosrc="BEGIN RETURN $1 + 1; END"))
    assert a != b


def test_definition_mutation_changes_fingerprint():
    a, _ = fingerprint_security_sensitive_function(row())
    b, _ = fingerprint_security_sensitive_function(row(function_definition="CREATE FUNCTION changed"))
    assert a != b


def test_sql_and_plpgsql_supported():
    assert fingerprint_security_sensitive_function(row(language="sql"))[0]
    assert fingerprint_security_sensitive_function(row(language="plpgsql"))[0]


def test_unsupported_security_language_fails_closed():
    with pytest.raises(UnsupportedSecurityFunctionLanguage):
        fingerprint_security_sensitive_function(row(language="c", probin="/tmp/lib.so", prosrc="sym"))
