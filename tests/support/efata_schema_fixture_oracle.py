from __future__ import annotations

import json
from pathlib import Path

from tools.efata_schema_collector.canonical import sha256_file, sha256_canonical


class OracleContractError(RuntimeError):
    pass


def load_qualification_oracle(path: Path, fixture_sql: Path) -> dict:
    oracle = json.loads(Path(path).read_text())
    if oracle.get("authorship_mode") != "INDEPENDENT_STATIC_CONTRACT":
        raise OracleContractError("oracle is not an independently authored static contract")
    if sha256_file(fixture_sql) != oracle.get("fixture_sql_sha256"):
        raise OracleContractError("fixture SQL SHA does not match frozen oracle binding")
    computed = sha256_canonical({
        key: value
        for key, value in oracle.items()
        if key != "ground_truth_sha256"
    })
    declared = oracle.get("ground_truth_sha256")
    if declared and declared != computed:
        raise OracleContractError("ground truth SHA mismatch")
    return oracle


def compare_required(oracle: dict, observed_objects: set[str], observed_security_facts: set[str]) -> dict:
    missing_objects = sorted(set(oracle.get("required_objects", ())) - observed_objects)
    missing_security = sorted(set(oracle.get("required_security_facts", ())) - observed_security_facts)
    return {
        "complete": not missing_objects and not missing_security,
        "missing_objects": missing_objects,
        "missing_security_facts": missing_security,
    }
