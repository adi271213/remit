"""Bounded reads of workflow blobs. No checkout, execution, or network calls."""
from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import os
import posixpath
from pathlib import Path
import re
import stat
import subprocess

MAX_FILE = 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 400
# Larger workflow files are fingerprinted, not read: unchanged ones stay quiet and
# changed ones make that file's analysis incomplete. Directory reads stop here.
MAX_HASHED = 64 * 1024 * 1024
# Local actions read on demand, beyond .github/workflows.
MAX_EXTRA_FILES = 100
WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")


class InputError(ValueError):
    pass


class Oversized(str):
    """Stands in for a workflow over MAX_FILE: equal when the content is equal, never parsed."""

    def __new__(cls, fingerprint: str):
        return super().__new__(cls, "\0oversized:" + fingerprint)


@dataclass
class Snapshot:
    identity: str
    files: dict[str, str]
    # Reads another repository file (such as a local action's action.yml) on demand.
    # Returns None when the file is absent, unsafe or over budget.
    read: Callable[[str], str | None] | None = field(default=None, compare=False, repr=False)


def merge_base(repo: str | Path, base: str, head: str) -> str | None:
    """The best common ancestor of two commits, or None when there isn't one locally."""
    try:
        commit = _git(repo, "merge-base", base, head).decode().strip()
    except InputError:
        return None
    return commit if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit) else None


def safe_relative(path: str) -> str | None:
    """Normalize a repository-relative path; reject absolute paths and escapes."""
    if not path or "\0" in path or "\\" in path or path.startswith("/"):
        return None
    normalized = posixpath.normpath(path)
    if normalized in (".", "") or normalized.startswith("../") or normalized == "..":
        return None
    return normalized


class _Budget:
    def __init__(self):
        self.files = 0
        self.bytes = 0

    def allow(self, size: int) -> bool:
        if self.files >= MAX_EXTRA_FILES or size > MAX_FILE or self.bytes + size > MAX_TOTAL:
            return False
        self.files += 1
        self.bytes += size
        return True


def _memoized(read):
    """Read each path once: repeated references must not use up the budget."""
    results = {}

    def cached(path: str) -> str | None:
        if path not in results:
            results[path] = read(path)
        return results[path]
    return cached


def _text(blob: bytes) -> str | None:
    try:
        return blob.decode("utf-8-sig", errors="strict")
    except UnicodeError:
        return None


def _stored(blobs) -> int:
    return sum(len(blob) for blob in blobs.values() if not isinstance(blob, Oversized))


def _fingerprint(start: bytes, handle) -> Oversized:
    digest, size = hashlib.sha256(start), len(start)
    while chunk := handle.read(1024 * 1024):
        size += len(chunk)
        if size > MAX_HASHED:
            raise InputError("A workflow exceeds the maximum readable size.")
        digest.update(chunk)
    return Oversized(digest.hexdigest())


def _decode(files: dict[str, bytes]) -> dict[str, str]:
    if len(files) > MAX_FILES or _stored(files) > MAX_TOTAL:
        raise InputError("Workflow snapshot exceeds file-count or total-byte limit.")
    result = {}
    for name, content in sorted(files.items()):
        if isinstance(content, Oversized):
            result[name] = content
            continue
        try:
            result[name] = content.decode("utf-8-sig", errors="strict")
        except UnicodeError as exc:
            raise InputError("A workflow is not valid UTF-8.") from exc
    return result


def directory(root: str | Path) -> Snapshot:
    root = Path(root).resolve()
    if not root.is_dir():
        raise InputError("Comparison directory does not exist.")
    for part in (root / ".github", root / ".github/workflows"):
        if part.is_symlink():
            raise InputError("Symlinked workflow directories are unsupported.")
    folder = root / ".github/workflows"
    blobs = {}
    if folder.exists():
        if not folder.is_dir():
            raise InputError("Workflow directory is not a directory.")
        names = sorted(folder.iterdir())
        for path in names:
            if not WORKFLOW.fullmatch(path.relative_to(root).as_posix()):
                continue
            if path.is_symlink() or not path.is_file():
                raise InputError("Workflow inputs must be regular files, not symlinks.")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise InputError("Workflow input is not a regular file.")
                with os.fdopen(fd, "rb", closefd=False) as handle:
                    content = handle.read(MAX_FILE + 1)
                    if len(content) > MAX_FILE:
                        content = _fingerprint(content, handle)
            finally:
                os.close(fd)
            blobs[path.relative_to(root).as_posix()] = content
            if len(blobs) > MAX_FILES or _stored(blobs) > MAX_TOTAL:
                raise InputError("Workflow snapshot exceeds file-count or total-byte limit.")
    files = _decode(blobs)
    digest = hashlib.sha256()
    for name, blob in sorted(blobs.items()):
        content = blob.encode() if isinstance(blob, Oversized) else blob
        digest.update(name.encode() + b"\0" + hashlib.sha256(content).digest())
    budget = _Budget()

    def read(path: str) -> str | None:
        relative = safe_relative(path)
        if relative is None:
            return None
        target = root / relative
        # Every component must be a real directory or file inside the root, not a link.
        current = root
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                return None
        if not target.is_file() or not target.resolve().is_relative_to(root):
            return None
        try:
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as handle:
                blob = handle.read(MAX_FILE + 1)
        finally:
            os.close(fd)
        return _text(blob) if budget.allow(len(blob)) else None

    return Snapshot("directory:sha256:" + digest.hexdigest(), files, _memoized(read))


def _git(repo: str | Path, *args: str) -> bytes:
    # Honor the explicit repository and immutable object IDs, not caller Git
    # redirections/config injection or locally installed replacement refs.
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(repo), *args],
            env=env, capture_output=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError("Local Git read failed or timed out.") from exc
    if result.returncode:
        raise InputError("Local Git object is unavailable; fetch history separately and retry.")
    return result.stdout


def git_snapshot(repo: str | Path, ref: str) -> Snapshot:
    commit = _git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise InputError("Git did not resolve a single commit.")
    entries = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--", ".github/workflows")
    blobs = {}
    total = 0
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        meta, name_bytes = entry.split(b"\t", 1)
        try:
            name = name_bytes.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise InputError("Workflow path is not UTF-8.") from exc
        if not WORKFLOW.fullmatch(name):
            continue
        mode, kind, oid = meta.decode().split()
        if mode not in ("100644", "100755") or kind != "blob":
            raise InputError("Git workflow input is not a regular file.")
        size = int(_git(repo, "cat-file", "-s", oid))
        if len(blobs) >= MAX_FILES:
            raise InputError("Workflow snapshot exceeds input limits.")
        if size > MAX_FILE:
            blobs[name] = Oversized(oid)  # the object ID already identifies the content
            continue
        total += size
        if total > MAX_TOTAL:
            raise InputError("Workflow snapshot exceeds input limits.")
        blobs[name] = _git(repo, "cat-file", "blob", oid)
    budget = _Budget()

    def read(path: str) -> str | None:
        relative = safe_relative(path)
        if relative is None:
            return None
        try:
            listing = _git(repo, "ls-tree", "-z", "--full-tree", commit, "--", relative).split(b"\0")[0]
            if not listing:
                return None
            meta = listing.split(b"\t", 1)[0].decode().split()
            if meta[0] not in ("100644", "100755") or meta[1] != "blob":
                return None
            if not budget.allow(int(_git(repo, "cat-file", "-s", meta[2]))):
                return None
            return _text(_git(repo, "cat-file", "blob", meta[2]))
        except (InputError, ValueError, IndexError):
            return None

    return Snapshot(commit, _decode(blobs), _memoized(read))
