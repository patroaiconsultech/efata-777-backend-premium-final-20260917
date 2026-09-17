from pathlib import Path

import pytest

from tests.support.efata_schema_fixture_harness import Postgres16FixtureHarness

ROOT = Path(__file__).parents[1]
FIXTURE_SQL = ROOT / "tests" / "fixtures" / "schema_collector" / "fixture_v1.sql"

AVAILABLE, REASON = Postgres16FixtureHarness.available()
pytestmark = pytest.mark.skipif(not AVAILABLE, reason=REASON)


def test_fixture_owned_root_is_removed_after_success():
    root = None
    with Postgres16FixtureHarness(FIXTURE_SQL) as harness:
        root = harness.runtime.root
        assert root.exists()
    assert root is not None
    assert not root.exists()


def test_fixture_owned_root_is_removed_after_exception():
    root = None
    with pytest.raises(RuntimeError, match="sentinel failure"):
        with Postgres16FixtureHarness(FIXTURE_SQL) as harness:
            root = harness.runtime.root
            raise RuntimeError("sentinel failure")
    assert root is not None
    assert not root.exists()
