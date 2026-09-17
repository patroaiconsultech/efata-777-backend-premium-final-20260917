from __future__ import annotations

import io
import stat
import unicodedata
import zipfile

import pytest

from orkio_v2.services.audit_archive_adapter import AuditArchiveAdapter, AuditArchiveError
from orkio_v2.services.audit_path_policy import AuditPathPolicy
from orkio_v2.services.audit_secret_policy import AuditSecretPolicyError


def verified_zip(tmp_path, builder):
    root = tmp_path / "root"
    root.mkdir()
    archive_path = root / "evidence.zip"
    builder(archive_path)
    policy = AuditPathPolicy({"e": root})
    return policy.open_verified_file(root_id="e", relative_path="evidence.zip")


def test_safe_zip_preflight_uses_actual_accounting_and_all_frozen_operations(tmp_path):
    def build(path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("docs/a.txt", "hello")
            z.writestr("docs/b.txt", "world")

    with verified_zip(tmp_path, build) as verified:
        adapter = AuditArchiveAdapter()
        report = adapter.preflight(verified)
        manifest = adapter.manifest(verified, offset=0, limit=1)
        metadata = adapter.file_metadata(verified, member_name="docs/a.txt")
        text = adapter.read_text_member(
            verified, member_name="docs/a.txt", offset=0, max_bytes=5
        )
        hashed = adapter.hash_member(verified, member_name="docs/a.txt")

    assert report["entry_count"] == 2
    assert report["declared_total_uncompressed_bytes"] == 10
    assert report["actual_total_decompressed_bytes"] == 10
    assert report["nested_archive_max_depth"] == 0
    assert all("actual_decompressed_bytes" in item for item in report["entries"])
    assert manifest["returned_entries"] == 1
    assert manifest["manifest_truncated"] is True
    assert metadata["name"] == "docs/a.txt"
    assert text["content"] == "hello"
    assert hashed["actual_decompressed_bytes"] == 5
    assert len(hashed["sha256"]) == 64


def test_zip_traversal_casefold_and_unicode_nfc_collisions_are_rejected(tmp_path):
    def build_bad(path):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("../escape.txt", "x")

    with verified_zip(tmp_path, build_bad) as verified:
        with pytest.raises(AuditArchiveError, match="UNSAFE_PATH"):
            AuditArchiveAdapter().preflight(verified)

    other = tmp_path / "case"
    other.mkdir()
    path = other / "collision.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("A.txt", "1")
        z.writestr("a.txt", "2")
    policy = AuditPathPolicy({"e": other})
    with policy.open_verified_file(root_id="e", relative_path="collision.zip") as vf:
        with pytest.raises(AuditArchiveError, match="DUPLICATE_PATH"):
            AuditArchiveAdapter().preflight(vf)

    unicode_root = tmp_path / "unicode"
    unicode_root.mkdir()
    unicode_zip = unicode_root / "collision.zip"
    nfc = "café.txt"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd
    with zipfile.ZipFile(unicode_zip, "w") as z:
        z.writestr(nfc, "1")
        z.writestr(nfd, "2")
    policy = AuditPathPolicy({"e": unicode_root})
    with policy.open_verified_file(root_id="e", relative_path="collision.zip") as vf:
        with pytest.raises(AuditArchiveError, match="DUPLICATE_PATH"):
            AuditArchiveAdapter().preflight(vf)


def test_zip_symlink_and_special_member_are_rejected(tmp_path):
    def build(path):
        with zipfile.ZipFile(path, "w") as z:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "target")

    with verified_zip(tmp_path, build) as verified:
        with pytest.raises(AuditArchiveError, match="SYMLINK"):
            AuditArchiveAdapter().preflight(verified)


def test_nested_archive_and_secret_like_member_names_are_rejected(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("inside.txt", "hello")

    def build_nested(path):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("nested.bin", inner.getvalue())

    with verified_zip(tmp_path, build_nested) as verified:
        with pytest.raises(AuditArchiveError, match="NESTED_ARCHIVE"):
            AuditArchiveAdapter().preflight(verified)

    secret_root = tmp_path / "secretname"
    secret_root.mkdir()
    secret_zip = secret_root / "secret.zip"
    with zipfile.ZipFile(secret_zip, "w") as z:
        z.writestr("config/api_token.txt", "not-a-real-token")
    policy = AuditPathPolicy({"e": secret_root})
    with policy.open_verified_file(root_id="e", relative_path="secret.zip") as vf:
        with pytest.raises(AuditArchiveError, match="SECRET_LIKE_MEMBER"):
            AuditArchiveAdapter().preflight(vf)

    env_root = tmp_path / "envname"
    env_root.mkdir()
    env_zip = env_root / "secret.zip"
    with zipfile.ZipFile(env_zip, "w") as z:
        z.writestr("config/.env.production", "SAFE_PLACEHOLDER=1")
    policy = AuditPathPolicy({"e": env_root})
    with policy.open_verified_file(root_id="e", relative_path="secret.zip") as vf:
        with pytest.raises(AuditArchiveError, match="SECRET_LIKE_MEMBER"):
            AuditArchiveAdapter().preflight(vf)


def test_actual_decompressed_stream_limit_is_enforced(tmp_path):
    def build(path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("large.txt", "A" * 1000)

    with verified_zip(tmp_path, build) as verified:
        adapter = AuditArchiveAdapter(
            max_stream_bytes=100,
            max_compression_ratio=1000,
            max_member_bytes=2000,
        )
        with pytest.raises(AuditArchiveError, match="STREAM_LIMIT"):
            adapter.preflight(verified)


def test_archive_binary_text_and_secret_page_boundary_are_fail_closed(tmp_path):
    def build_binary(path):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("docs/a.txt", b"hello\xffworld")

    with verified_zip(tmp_path, build_binary) as verified:
        with pytest.raises(AuditArchiveError, match="BINARY_AS_TEXT"):
            AuditArchiveAdapter().read_text_member(
                verified, member_name="docs/a.txt", max_bytes=64
            )

    secret_root = tmp_path / "secretcontent"
    secret_root.mkdir()
    secret_zip = secret_root / "evidence.zip"
    with zipfile.ZipFile(secret_zip, "w") as z:
        z.writestr(
            "docs/a.txt",
            b"prefix-sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-suffix",
        )
    policy = AuditPathPolicy({"e": secret_root})
    with policy.open_verified_file(root_id="e", relative_path="evidence.zip") as vf:
        with pytest.raises(AuditSecretPolicyError, match="SECRET_CONTENT_BLOCKED"):
            AuditArchiveAdapter().read_text_member(
                vf, member_name="docs/a.txt", offset=16, max_bytes=8
            )
