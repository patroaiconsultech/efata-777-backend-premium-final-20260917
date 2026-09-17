from __future__ import annotations

from .canonical import (
    normalize_sensitive_definition,
    sha256_bytes,
    sha256_canonical,
    sha256_nullable,
)

SUPPORTED_SECURITY_FUNCTION_LANGUAGES = frozenset({"sql", "plpgsql"})


class UnsupportedSecurityFunctionLanguage(RuntimeError):
    pass


class FunctionConfigCanonicalizationError(ValueError):
    pass


def canonicalize_proconfig(values) -> tuple[tuple[str, str], ...]:
    if values in (None, (), []):
        return ()
    pairs: dict[str, str] = {}
    for item in values:
        text = str(item)
        if "=" not in text:
            raise FunctionConfigCanonicalizationError(
                "CAPTURE.FUNCTION_CONFIG_UNCANONICAL"
            )
        key, value = text.split("=", 1)
        key = key.strip().lower()
        if not key or key in pairs:
            raise FunctionConfigCanonicalizationError(
                "CAPTURE.FUNCTION_CONFIG_UNCANONICAL"
            )
        pairs[key] = value
    return tuple(sorted(pairs.items()))


def fingerprint_security_sensitive_function(row: dict) -> tuple[str, dict]:
    language = str(row.get("language") or "").lower()
    if language not in SUPPORTED_SECURITY_FUNCTION_LANGUAGES:
        raise UnsupportedSecurityFunctionLanguage(
            f"CAPTURE.SECURITY_SENSITIVE_FUNCTION_LANGUAGE_UNSUPPORTED:{language}"
        )

    definition = row.get("function_definition")
    if not isinstance(definition, str):
        raise ValueError("CAPTURE.SECURITY_SENSITIVE_DEFINITION_UNOBSERVABLE")

    config = canonicalize_proconfig(row.get("proconfig"))
    body_sha256 = sha256_bytes(normalize_sensitive_definition(str(row.get("prosrc") or "")))
    definition_sha256 = sha256_bytes(normalize_sensitive_definition(definition))

    material = {
        "identity": f'{row["schema_name"]}.{row["function_name"]}({row.get("identity_arguments") or ""})',
        "language": language,
        "prokind": row.get("prokind"),
        "security_definer": bool(row.get("prosecdef")),
        "volatility": row.get("provolatile"),
        "parallel": row.get("proparallel"),
        "leakproof": bool(row.get("proleakproof")),
        "strict": bool(row.get("proisstrict")),
        "config": config,
        "prosrc_sha256": body_sha256,
        "probin_sha256": sha256_nullable(row.get("probin")),
        "definition_sha256": definition_sha256,
        "has_prosqlbody": bool(row.get("has_prosqlbody")),
    }
    return sha256_canonical(material), material
