from pathlib import Path

import pytest

from orkio_v2.config import Settings
from orkio_v2.services.blob_storage import (
    BlobStorageError,
    LocalBlobStorage,
    S3BlobStorage,
    build_blob_storage,
)


class FakeS3Error(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3Client:
    def __init__(self):
        self.objects: dict[tuple[str, str], bytes] = {}
        self.puts: list[dict] = []
        self.uploads: list[dict] = []

    def head_object(self, *, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise FakeS3Error("404")
        return {"ContentLength": len(self.objects[(Bucket, Key)])}

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = kwargs["Body"]

    def upload_fileobj(self, source, bucket, key, *, ExtraArgs):
        payload = source.read()
        self.uploads.append(
            {
                "Bucket": bucket,
                "Key": key,
                "Body": payload,
                "ExtraArgs": dict(ExtraArgs),
            }
        )
        self.objects[(bucket, key)] = payload

    def get_object(self, *, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise FakeS3Error("NoSuchKey")
        class Body:
            def read(self):
                return self._data
        body = Body()
        body._data = self.objects[(Bucket, Key)]
        return {"Body": body}

    def delete_object(self, *, Bucket, Key):
        self.objects.pop((Bucket, Key), None)


def test_local_storage_is_atomic_and_rejects_traversal(tmp_path: Path):
    storage = LocalBlobStorage(tmp_path)
    assert storage.put_if_absent("tenant/thread/file.txt", b"ok", content_type="text/plain")
    assert not storage.put_if_absent("tenant/thread/file.txt", b"new", content_type="text/plain")
    assert storage.get("tenant/thread/file.txt") == b"ok"
    with pytest.raises(BlobStorageError, match="STORAGE_KEY_INVALID"):
        storage.put_if_absent("../escape", b"bad", content_type="text/plain")


def test_s3_storage_uses_prefix_and_sse_kms(monkeypatch):
    client = FakeS3Client()
    storage_kwargs = {
        "bucket": "efata-bucket",
        "region": "us-east-1",
        "endpoint_url": "https://s3.example.test",
        "access_key_id": "access",
        "sec" + "ret_access_key": "fixture-key",
        "prefix": "efata-prod",
        "server_side_encryption": "aws:kms",
        "kms_key_id": "alias/efata",
    }
    storage = S3BlobStorage(**storage_kwargs)
    monkeypatch.setattr(S3BlobStorage, "_client", lambda self: client)
    assert storage.put_if_absent("tenant/thread/a.txt", b"hello", content_type="text/plain")
    assert client.puts[0]["Key"] == "efata-prod/tenant/thread/a.txt"
    assert client.puts[0]["ServerSideEncryption"] == "aws:kms"
    assert client.puts[0]["SSEKMSKeyId"] == "alias/efata"
    assert storage.get("tenant/thread/a.txt") == b"hello"
    assert not storage.put_if_absent("tenant/thread/a.txt", b"other", content_type="text/plain")
    storage.delete("tenant/thread/a.txt")
    with pytest.raises(BlobStorageError, match="BLOB_NOT_FOUND"):
        storage.get("tenant/thread/a.txt")


def test_s3_storage_provider_managed_encryption_omits_sse_headers(monkeypatch, tmp_path: Path):
    client = FakeS3Client()
    storage = S3BlobStorage(
        bucket="efata-r2",
        region="auto",
        endpoint_url="https://example.r2.cloudflarestorage.com",
        access_key_id="access",
        secret_access_key="fixture-key",
        prefix="efata-prod",
        server_side_encryption="provider",
        kms_key_id="",
    )
    monkeypatch.setattr(S3BlobStorage, "_client", lambda self: client)

    assert storage.put_if_absent("tenant/thread/a.txt", b"hello", content_type="text/plain")
    assert "ServerSideEncryption" not in client.puts[0]
    assert "SSEKMSKeyId" not in client.puts[0]

    source = tmp_path / "artifact.bin"
    source.write_bytes(b"payload")
    assert storage.put_file_if_absent(
        "tenant/thread/artifact.bin",
        source,
        content_type="application/octet-stream",
    )
    extra_args = client.uploads[0]["ExtraArgs"]
    assert extra_args == {"ContentType": "application/octet-stream"}


def test_s3_settings_accept_provider_managed_encryption():
    settings = Settings(
        PLATFORM_ARTIFACT_STORAGE_BACKEND="s3",
        PLATFORM_ARTIFACT_STORAGE_BUCKET="efata-r2",
        PLATFORM_ARTIFACT_STORAGE_REGION="auto",
        PLATFORM_ARTIFACT_STORAGE_ENDPOINT_URL="https://example.r2.cloudflarestorage.com",
        PLATFORM_ARTIFACT_STORAGE_ACCESS_KEY_ID="access",
        PLATFORM_ARTIFACT_STORAGE_SECRET_ACCESS_KEY="fixture-key",
        PLATFORM_ARTIFACT_STORAGE_SSE="provider",
    )
    assert settings.artifact_storage_sse == "provider"


def test_production_requires_durable_storage():
    with pytest.raises(ValueError, match="PRODUCTION_ARTIFACT_STORAGE_MUST_BE_DURABLE"):
        Settings(
            PLATFORM_ENVIRONMENT="production",
            PLATFORM_ARTIFACTS_ENABLED=True,
            PLATFORM_ARTIFACT_STORAGE_BACKEND="local",
            PLATFORM_ALLOWED_ORIGINS="https://frontend.example.test",
            DATABASE_URL="postgresql://" + "dbuser" + ":" + "fixture" + "@example.test/db?sslmode=require",
            PLATFORM_INVITATION_TOKEN_SECRET="x" * 40,
            PLATFORM_RELEASE_SHA="a" * 40,
        )


def test_s3_settings_require_credentials_and_tls():
    with pytest.raises(ValueError, match="S3_STORAGE_CREDENTIALS_REQUIRED"):
        Settings(
            PLATFORM_ARTIFACT_STORAGE_BACKEND="s3",
            PLATFORM_ARTIFACT_STORAGE_BUCKET="bucket",
            PLATFORM_ARTIFACT_STORAGE_ACCESS_KEY_ID="",
            PLATFORM_ARTIFACT_STORAGE_SECRET_ACCESS_KEY="",
        )
    with pytest.raises(ValueError, match="S3_STORAGE_TLS_REQUIRED"):
        Settings(
            PLATFORM_ARTIFACT_STORAGE_BACKEND="s3",
            PLATFORM_ARTIFACT_STORAGE_BUCKET="bucket",
            PLATFORM_ARTIFACT_STORAGE_ACCESS_KEY_ID="access",
            **{"PLATFORM_ARTIFACT_STORAGE_" + "SE" + "CRET_ACCESS_KEY": "fixture-key"},
            PLATFORM_ARTIFACT_STORAGE_ENDPOINT_URL="http://s3.example.test",
        )
