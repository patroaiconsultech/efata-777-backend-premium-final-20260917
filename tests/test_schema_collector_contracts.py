import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.efata_schema_collector.canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    sha256_canonical,
)
from tools.efata_schema_collector.contracts import CollectorSessionProfile
from tools.efata_schema_collector.query_pack import QUERY_PACK_SHA256, QUERY_SPECS


def test_canonical_object_order_is_stable():
    assert canonical_json_bytes({"b": 2, "a": 1}) == canonical_json_bytes({"a": 1, "b": 2})
    assert sha256_canonical({"b": [2, 1], "a": None}) == sha256_canonical({"a": None, "b": [2, 1]})


def test_canonical_array_order_is_preserved():
    assert sha256_canonical({"x": [1, 2]}) != sha256_canonical({"x": [2, 1]})


def test_canonical_float_is_forbidden():
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"money": 0.1})


def test_contracts_are_frozen_and_forbid_extra():
    profile = CollectorSessionProfile()
    with pytest.raises(ValidationError):
        CollectorSessionProfile(unexpected=True)
    with pytest.raises(ValidationError):
        profile.search_path = "public"


def test_query_pack_is_closed_and_hashed():
    names = [q.name for q in QUERY_SPECS]
    assert len(names) == len(set(names))
    assert len(QUERY_PACK_SHA256) == 64
    assert all("user_sql" not in q.sql.lower() for q in QUERY_SPECS)
