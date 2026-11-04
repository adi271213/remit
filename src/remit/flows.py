"""What code a job runs: third-party actions and fetches of pull request code.

Steps are followed into local composite actions (`uses: ./path`) and local
reusable workflows (`uses: ./.github/workflows/x.yml`), with bounded depth.
Nothing is executed; files are read through the snapshot's bounded reader.
"""
from dataclasses import dataclass
import re

import yaml

from .sources import Snapshot, safe_relative

# Triggers whose runs hold the base repository's secrets and write token while
# being caused by people outside the repository.
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")
FIRST_PARTY_OWNERS = {"actions", "github"}
MAX_DEPTH = 4
LOCAL_WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.ya?ml")

# Pull request content addressed by commit: fixed once the event fires.
IMMUTABLE_REF = re.compile(
    r"github\s*\.\s*event\s*\.\s*(?:pull_request\s*\.\s*(?:head\s*\.\s*sha|merge_commit_sha)"
    r"|workflow_run\s*\.\s*head_sha)", re.IGNORECASE)
# Pull request content addressed by a name the author can move by pushing.
MUTABLE_REF = re.compile(
    r"github\s*\.\s*(?:head_ref|event\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*(?:ref|repo)"
    r"|workflow_run\s*\.\s*(?:head_branch|head_repository)))|refs/pull/", re.IGNORECASE)
SCRIPT_FETCH = re.compile(r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|pull)\b[^\n]*\bpull/", re.IGNORECASE)
SCRIPT_CHECKOUT = re.compile(r"\bgit\s+(?:checkout|switch|reset|fetch)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Code:
    """Third-party code a job runs."""
    target: str  # normalized owner/repo[/path], without the ref
    uses: str    # as written
    file: str
    line: int | None


@dataclass(frozen=True)
class Fetch:
    """A step that brings pull request content into the job."""
    kind: str    # checkout | script | artifact
    ref: str     # the expression or command that selects the content
    mutable: bool
    file: str
    line: int | None


def third_party_target(value: str) -> str | None:
    """owner/repo[/path] for code from outside the repository, else None."""
    if not isinstance(value, str) or value.startswith(("./", "docker://")) or "${{" in value:
        return None
    target = value.split("@", 1)[0].strip().casefold()
    if "/" not in target or target.split("/", 1)[0] in FIRST_PARTY_OWNERS:
        return None
    return target


def _key(node, name):
    """(line, value node) for a mapping key, else (None, None)."""
    if isinstance(node, yaml.nodes.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.nodes.ScalarNode) and key.value == name:
                return key.start_mark.line + 1, value
    return None, None


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def fetch_of(step: dict) -> tuple[str, str, bool] | None:
    """(kind, selector, mutable) when the step brings pull request content in."""
    uses = step.get("uses")
    uses = uses.casefold() if isinstance(uses, str) else ""
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    if uses.startswith("actions/checkout@") or uses == "actions/checkout":
        ref = options.get("ref") if isinstance(options.get("ref"), str) else ""
        repository = options.get("repository") if isinstance(options.get("repository"), str) else ""
        selector = ref or repository
        if not any(pattern.search(text) for text in (ref, repository) for pattern in (IMMUTABLE_REF, MUTABLE_REF)):
            return None
        if ref:
            mutable = bool(MUTABLE_REF.search(ref)) and not IMMUTABLE_REF.search(ref)
        else:  # the head repository's default branch
            mutable = True
        return "checkout", selector.strip(), mutable
    if uses.startswith("dawidd6/action-download-artifact@") or (
            uses.startswith("actions/download-artifact@")
            and any("workflow_run" in text for text in _strings(options))):
        # Compare by action, not version: a ref bump is not a new download.
        return "artifact", step["uses"].split("@", 1)[0], False
    run = step.get("run")
    if isinstance(run, str):
        if SCRIPT_FETCH.search(run):
            line = next(line for line in run.splitlines() if SCRIPT_FETCH.search(line))
            return "script", line.strip(), True
        # The git command and the pull request reference must be on the same line.
        for line in run.splitlines():
            if SCRIPT_CHECKOUT.search(line) and (IMMUTABLE_REF.search(line) or MUTABLE_REF.search(line)):
                return "script", line.strip(), bool(MUTABLE_REF.search(line)) and not IMMUTABLE_REF.search(line)
    return None


class LocalCode:
    """Follows local actions and reusable workflows within one snapshot."""

    def __init__(self, snapshot: Snapshot, load_yaml):
        self.snapshot = snapshot
        self.load_yaml = load_yaml
        self.cache = {}
        self.texts = {}
        self.issues = []    # reasons a local reference could not be followed
        self.touched = set()

    def text(self, path: str) -> str | None:
        if path in self.snapshot.files:
            return self.snapshot.files[path]
        if path not in self.texts:
            self.texts[path] = self.snapshot.read(path) if self.snapshot.read else None
        return self.texts[path]

    def _load(self, path: str, kind: str):
        if path not in self.cache:
            text = self.text(path)
            loaded = None
            if text is None:
                # Without a reader (for example the historical replay) local code is not followed.
                if self.snapshot.read is not None or path.startswith(".github/workflows/"):
                    self.issues.append(f"Local {kind} {path} could not be read.")
            else:
                try:
                    document, node = self.load_yaml(text)
                    if isinstance(document, dict):
                        loaded = document, node
                    else:
                        self.issues.append(f"Local {kind} {path} is not a mapping.")
                except (ValueError, yaml.YAMLError, RecursionError):
                    self.issues.append(f"Local {kind} {path} is invalid or exceeds analysis limits.")
            self.cache[path] = loaded
        if self.cache[path] is not None:
            self.touched.add(path)
        return self.cache[path]

    def job(self, file: str, job: dict, node=None, depth: int = 0, seen: frozenset = frozenset()):
        """(codes, fetches) for one job, including code reached through local references."""
        codes, fetches = [], []
        if isinstance(job.get("uses"), str):
            self._uses(job["uses"], file, _key(node, "uses")[0], codes, fetches, depth, seen, True)
        self._steps(file, job.get("steps"), _key(node, "steps")[1], codes, fetches, depth, seen)
        return codes, fetches

    def _steps(self, file, steps, steps_node, codes, fetches, depth, seen):
        if not isinstance(steps, list):
            return
        nodes = steps_node.value if isinstance(steps_node, yaml.nodes.SequenceNode) else []
        nodes = nodes if len(nodes) == len(steps) else [None] * len(steps)
        for step, node in zip(steps, nodes):
            if not isinstance(step, dict):
                continue
            found = fetch_of(step)
            if found:
                line = _key(node, "uses")[0] or _key(node, "run")[0]
                fetches.append(Fetch(found[0], found[1], found[2], file, line))
            if isinstance(step.get("uses"), str):
                self._uses(step["uses"], file, _key(node, "uses")[0], codes, fetches, depth, seen, False)

    def _uses(self, value, file, line, codes, fetches, depth, seen, job_level):
        if not value.startswith("./"):
            target = third_party_target(value)
            if target:
                codes.append(Code(target, value, file, line))
            return
        if depth >= MAX_DEPTH:
            self.issues.append(f"Local references nest deeper than {MAX_DEPTH} levels at {file}.")
            return
        relative = safe_relative(value[2:].split("@", 1)[0].strip()) if value.strip() != "./" else ""
        if relative is None:
            self.issues.append(f"Local reference {value} in {file} is outside the repository.")
            return
        if job_level:
            if not LOCAL_WORKFLOW.fullmatch(relative) or relative in seen:
                return
            loaded = self._load(relative, "workflow")
            if loaded is None:
                return
            document, node = loaded
            jobs_line, jobs_node = _key(node, "jobs")
            for name, called in (document.get("jobs") or {}).items():
                if isinstance(called, dict):
                    more = self.job(relative, called, _key(jobs_node, name)[1], depth + 1, seen | {relative})
                    codes.extend(more[0])
                    fetches.extend(more[1])
            return
        base = f"{relative}/" if relative else ""
        for candidate in (base + "action.yml", base + "action.yaml"):
            if candidate in seen:
                return
            text = self.text(candidate)
            if text is None:
                continue
            loaded = self._load(candidate, "action")
            if loaded is None:
                return
            document, node = loaded
            runs = document.get("runs")
            if isinstance(runs, dict) and str(runs.get("using", "")).casefold() == "composite":
                runs_node = _key(node, "runs")[1]
                self._steps(candidate, runs.get("steps"), _key(runs_node, "steps")[1],
                            codes, fetches, depth + 1, seen | {candidate})
            return
        if self.snapshot.read is not None:
            self.issues.append(f"Local action {relative or '.'} has no readable action.yml.")

    def dependencies(self, document: dict) -> set[str]:
        """Local files reachable from a workflow's jobs."""
        self.touched = set()
        for job in (document.get("jobs") or {}).values():
            if isinstance(job, dict):
                self.job("", job)
        return set(self.touched)


def gate(document: dict, job: dict, triggers: set[str]) -> str | None:
    """How the workflow waits for a person before running, if it does."""
    on = document.get("on")
    if isinstance(on, dict):
        target = on.get("pull_request_target")
        types = target.get("types") if isinstance(target, dict) else None
        if isinstance(types, list) and "labeled" in types:
            return "a label"
    if "issue_comment" in triggers:
        return "a comment command"
    condition = job.get("if")
    if isinstance(condition, str):
        if "label" in condition:
            return "a label"
        if "comment" in condition:
            return "a comment command"
    if job.get("environment"):
        return "environment approval"
    return None
