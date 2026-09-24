from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
import hashlib
from pathlib import Path
from typing import Iterable


_DEFAULT_PREFIXES = ("src", "migrations", "scripts", "tests")
_DEFAULT_SUFFIXES = frozenset({".py", ".json", ".toml", ".ini", ".md", ".txt", ".yml", ".yaml"})
_SKIP_PARTS = frozenset({".git", ".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv", "venv", "node_modules"})
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})


class ArchitectureIndexError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PythonStructure:
    classes: tuple[str, ...]
    functions: tuple[str, ...]
    imports: tuple[str, ...]
    route_decorators: tuple[str, ...]
    parse_error: str | None = None


@dataclass(frozen=True, slots=True)
class IndexedFile:
    path: str
    sha256: str
    size_bytes: int
    suffix: str
    python: PythonStructure | None = None


@dataclass(frozen=True, slots=True)
class ArchitectureIndex:
    schema_version: str
    root_label: str
    file_count: int
    total_bytes: int
    tree_sha256: str
    files: tuple[IndexedFile, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Import):
        return ",".join(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        prefix = "." * int(node.level or 0)
        return prefix + (node.module or "")
    return None


def _decorator_name(node: ast.AST) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute):
        base = target.value
        if isinstance(base, ast.Name):
            return f"{base.id}.{target.attr}"
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return ""


def _python_structure(data: bytes, *, path: str) -> PythonStructure:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return PythonStructure((), (), (), (), "NON_UTF8_PYTHON_SOURCE")
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        return PythonStructure(
            (), (), (), (),
            f"SYNTAX_ERROR:{exc.lineno or 0}:{exc.offset or 0}",
        )

    classes: list[str] = []
    functions: list[str] = []
    imports: list[str] = []
    routes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
            for decorator in node.decorator_list:
                name = _decorator_name(decorator)
                method = name.rsplit(".", 1)[-1]
                if method in _HTTP_METHODS:
                    routes.append(f"{name}:{node.name}")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            name = _module_name(node)
            if name:
                imports.append(name)

    return PythonStructure(
        classes=tuple(sorted(set(classes))),
        functions=tuple(sorted(set(functions))),
        imports=tuple(sorted(set(imports))),
        route_decorators=tuple(sorted(set(routes))),
        parse_error=None,
    )


def _candidate_files(
    root: Path,
    *,
    prefixes: Iterable[str],
    suffixes: frozenset[str],
) -> list[Path]:
    candidates: list[Path] = []
    for raw_prefix in prefixes:
        prefix = (root / raw_prefix).resolve()
        if not prefix.exists():
            continue
        if root != prefix and root not in prefix.parents:
            raise ArchitectureIndexError("ARCHITECTURE_PREFIX_OUTSIDE_ROOT")
        if prefix.is_symlink():
            raise ArchitectureIndexError("ARCHITECTURE_SYMLINK_PREFIX_DENIED")
        if prefix.is_file():
            scan = (prefix,)
        else:
            scan = prefix.rglob("*")
        for path in scan:
            if not path.is_file():
                continue
            if path.is_symlink():
                continue
            rel = path.relative_to(root)
            if any(part in _SKIP_PARTS for part in rel.parts):
                continue
            if path.suffix.lower() not in suffixes:
                continue
            candidates.append(path)
    return sorted(set(candidates), key=lambda p: p.relative_to(root).as_posix())


def build_architecture_index(
    repository_root: str | Path,
    *,
    root_label: str = "EFATA_BACKEND_SOURCE",
    prefixes: Iterable[str] = _DEFAULT_PREFIXES,
    suffixes: frozenset[str] = _DEFAULT_SUFFIXES,
    max_files: int = 5000,
    max_file_bytes: int = 2_000_000,
    max_total_bytes: int = 64_000_000,
) -> ArchitectureIndex:
    """Build a bounded, deterministic, read-only structural source index.

    File contents are never returned. The index contains hashes and Python
    structure names only, making it suitable as evidence input for internal
    agents without injecting arbitrary repository content into their prompts.
    """
    root = Path(repository_root).resolve()
    if not root.exists() or not root.is_dir():
        raise ArchitectureIndexError("ARCHITECTURE_ROOT_NOT_FOUND")
    if root.is_symlink():
        raise ArchitectureIndexError("ARCHITECTURE_ROOT_SYMLINK_DENIED")
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise ArchitectureIndexError("ARCHITECTURE_LIMIT_INVALID")

    candidates = _candidate_files(root, prefixes=prefixes, suffixes=suffixes)
    if len(candidates) > max_files:
        raise ArchitectureIndexError("ARCHITECTURE_FILE_LIMIT_EXCEEDED")

    indexed: list[IndexedFile] = []
    total = 0
    digest = hashlib.sha256()
    for path in candidates:
        resolved = path.resolve()
        if root != resolved and root not in resolved.parents:
            raise ArchitectureIndexError("ARCHITECTURE_PATH_ESCAPE")
        size = path.stat().st_size
        if size > max_file_bytes:
            raise ArchitectureIndexError("ARCHITECTURE_FILE_SIZE_LIMIT_EXCEEDED")
        total += size
        if total > max_total_bytes:
            raise ArchitectureIndexError("ARCHITECTURE_TOTAL_SIZE_LIMIT_EXCEEDED")
        data = path.read_bytes()
        rel = path.relative_to(root).as_posix()
        file_sha = _sha256_bytes(data)
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_sha.encode("ascii"))
        digest.update(b"\n")
        indexed.append(
            IndexedFile(
                path=rel,
                sha256=file_sha,
                size_bytes=len(data),
                suffix=path.suffix.lower(),
                python=_python_structure(data, path=rel)
                if path.suffix.lower() == ".py"
                else None,
            )
        )

    return ArchitectureIndex(
        schema_version="EFATA_ARCH_INDEX_V1",
        root_label=root_label,
        file_count=len(indexed),
        total_bytes=total,
        tree_sha256=digest.hexdigest(),
        files=tuple(indexed),
    )


def find_symbol(
    index: ArchitectureIndex,
    *,
    path: str,
    symbol: str,
    kind: str = "class",
) -> bool:
    for item in index.files:
        if item.path != path or item.python is None:
            continue
        if kind == "class":
            return symbol in item.python.classes
        if kind == "function":
            return symbol in item.python.functions
        raise ArchitectureIndexError("ARCHITECTURE_SYMBOL_KIND_INVALID")
    return False


def contains_marker(
    repository_root: str | Path,
    *,
    path: str,
    marker: str,
    max_bytes: int = 2_000_000,
) -> bool:
    """Bounded exact marker probe for governed self-model facts.

    This is intentionally a targeted probe, not a repository-wide content
    search. It returns only a boolean and never exposes source content.
    """
    root = Path(repository_root).resolve()
    target = (root / path).resolve()
    if root != target and root not in target.parents:
        raise ArchitectureIndexError("ARCHITECTURE_PATH_ESCAPE")
    if not target.exists() or not target.is_file() or target.is_symlink():
        return False
    if target.stat().st_size > max_bytes:
        raise ArchitectureIndexError("ARCHITECTURE_FILE_SIZE_LIMIT_EXCEEDED")
    return marker in target.read_text(encoding="utf-8", errors="replace")
