"""Bounded reads of workflow blobs. No checkout, execution, or network calls."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_FILE = 256 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MAX_FILES = 200
WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")


class InputError(ValueError):
    pass


@dataclass
class Snapshot:
    identity: str
    files: dict[str, str]


def _decode(files: dict[str, bytes]) -> dict[str, str]:
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_TOTAL:
        raise InputError("Workflow snapshot exceeds file-count or total-byte limit.")
    result = {}
    for name, content in sorted(files.items()):
        if len(content) > MAX_FILE:
            raise InputError("A workflow exceeds the per-file byte limit.")
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
            finally:
                os.close(fd)
            blobs[path.relative_to(root).as_posix()] = content
            if len(blobs) > MAX_FILES or sum(map(len, blobs.values())) > MAX_TOTAL:
                raise InputError("Workflow snapshot exceeds file-count or total-byte limit.")
    files = _decode(blobs)
    digest = hashlib.sha256()
    for name, blob in sorted(blobs.items()):
        digest.update(name.encode() + b"\0" + hashlib.sha256(blob).digest())
    return Snapshot("directory:sha256:" + digest.hexdigest(), files)


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
        total += size
        if size > MAX_FILE or total > MAX_TOTAL or len(blobs) >= MAX_FILES:
            raise InputError("Workflow snapshot exceeds input limits.")
        blobs[name] = _git(repo, "cat-file", "blob", oid)
    return Snapshot(commit, _decode(blobs))
