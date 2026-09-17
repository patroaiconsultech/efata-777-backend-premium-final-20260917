from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping


class AuditPathPolicyError(RuntimeError):
    code = "AUDIT_PATH_NOT_ALLOWED"



_SECRET_LIKE_BASENAMES = {
    ".env",
    ".aws",
    ".ssh",
    ".gnupg",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "secrets",
    "secrets.json",
}
_SECRET_LIKE_SUFFIXES = (".key", ".pem", ".p12", ".pfx")


def _assert_path_not_secret_like(parts: tuple[str, ...]) -> None:
    for part in parts:
        folded = part.casefold()
        if (
            folded in _SECRET_LIKE_BASENAMES
            or folded.startswith(".env.")
            or folded.endswith(_SECRET_LIKE_SUFFIXES)
        ):
            raise AuditPathPolicyError("AUDIT_PATH_SECRET_LIKE_FORBIDDEN")


@dataclass(slots=True)
class VerifiedFile:
    root_id: str
    relative_path: str
    fd: int
    size: int
    device: int
    inode: int

    def duplicate_fd(self) -> int:
        return os.dup(self.fd)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "VerifiedFile":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _safe_components(relative_path: str) -> tuple[str, ...]:
    if not relative_path or "\\" in relative_path or "\x00" in relative_path:
        raise AuditPathPolicyError("AUDIT_PATH_NOT_ALLOWED")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute():
        raise AuditPathPolicyError("AUDIT_PATH_NOT_ALLOWED")
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AuditPathPolicyError("AUDIT_PATH_NOT_ALLOWED")
    _assert_path_not_secret_like(parts)
    return parts


class AuditPathPolicy:
    """Resolve only server-registered roots and return an identity-bound file handle."""

    def __init__(self, roots: Mapping[str, Path | str]) -> None:
        normalized: dict[str, Path] = {}
        for root_id, raw in roots.items():
            key = root_id.strip()
            path = Path(raw)
            if not key or not path.is_absolute():
                raise AuditPathPolicyError("AUDIT_ROOT_INVALID")
            if path.is_symlink() or not path.is_dir():
                raise AuditPathPolicyError("AUDIT_ROOT_INVALID")
            normalized[key] = path
        self._roots = normalized

    def open_verified_file(self, *, root_id: str, relative_path: str) -> VerifiedFile:
        try:
            root = self._roots[root_id]
        except KeyError as exc:
            raise AuditPathPolicyError("AUDIT_ROOT_NOT_REGISTERED") from exc
        parts = _safe_components(relative_path)

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        odirectory = getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(root, os.O_RDONLY | odirectory | nofollow)
        opened_dirs: list[int] = [directory_fd]
        try:
            current_fd = directory_fd
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | odirectory | nofollow,
                    dir_fd=current_fd,
                )
                opened_dirs.append(next_fd)
                st = os.fstat(next_fd)
                if not stat.S_ISDIR(st.st_mode):
                    raise AuditPathPolicyError("AUDIT_PATH_NOT_ALLOWED")
                current_fd = next_fd

            name = parts[-1]
            before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise AuditPathPolicyError("AUDIT_PATH_SYMLINK_FORBIDDEN")
            if not stat.S_ISREG(before.st_mode):
                raise AuditPathPolicyError("AUDIT_PATH_SPECIAL_FILE_FORBIDDEN")

            fd = os.open(name, os.O_RDONLY | nofollow, dir_fd=current_fd)
            after = os.fstat(fd)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or not stat.S_ISREG(after.st_mode)
            ):
                os.close(fd)
                raise AuditPathPolicyError("AUDIT_PATH_IDENTITY_CHANGED")

            return VerifiedFile(
                root_id=root_id,
                relative_path="/".join(parts),
                fd=fd,
                size=int(after.st_size),
                device=int(after.st_dev),
                inode=int(after.st_ino),
            )
        except OSError as exc:
            raise AuditPathPolicyError("AUDIT_PATH_NOT_ALLOWED") from exc
        finally:
            for fd_to_close in reversed(opened_dirs):
                try:
                    os.close(fd_to_close)
                except OSError:
                    pass
