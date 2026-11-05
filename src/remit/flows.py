"""What code a job runs: third-party actions and fetches of pull request code.

Steps are followed into local composite actions (`uses: ./path`) and local
reusable workflows (`uses: ./.github/workflows/x.yml`), with bounded depth.
GitHub's same-repository form (`uses: $/path`) is followed the same way.
Nothing is executed; files are read through the snapshot's bounded reader.
"""
from dataclasses import dataclass, field
import re

import yaml

from .sources import Snapshot, safe_relative

# Triggers whose runs hold the base repository's secrets and write token while
# being caused by people outside the repository.
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")
FIRST_PARTY_OWNERS = {"actions", "github"}
MAX_DEPTH = 10  # GitHub allows 10 levels of nested reusable workflows and composite actions
LOCAL_WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.ya?ml")
# ./ resolves in the runner's workspace and $/ in the workflow's own repository at the running
# commit; for an analysis of one commit both name a file in this snapshot.
LOCAL_PREFIXES = ("./", "$/")
FULL_SHA = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")

# Pull request content addressed by commit: fixed once the event fires.
IMMUTABLE_REF = re.compile(
    r"github\s*\.\s*event\s*\.\s*(?:pull_request\s*\.\s*(?:head\s*\.\s*sha|merge_commit_sha)"
    r"|workflow_run\s*\.\s*head_sha)", re.IGNORECASE)
# Pull request content addressed by a name the author can move by pushing.
MUTABLE_REF = re.compile(
    r"github\s*\.\s*(?:head_ref|event\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*(?:ref|repo)"
    r"|workflow_run\s*\.\s*(?:head_branch|head_repository)))|refs/pull/", re.IGNORECASE)
SCRIPT_FETCH = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|pull)\b[^\n]*\bpull/"
    # The pull request's diff applied to the workspace, as it is when the job runs.
    r"|\bgh\s+pr\s+diff\b[^\n]*\|\s*(?:git\s+apply|git\s+am|patch)\b", re.IGNORECASE)
# Commands that put the content a reference names into the workspace. The reference (or a
# variable carrying it) must be on the same line.
SCRIPT_CHECKOUT = re.compile(r"\bgit\s+(?:checkout|switch|reset|fetch|clone)\b|\bgh\s+repo\s+clone\b", re.IGNORECASE)
# Downloads count only when they fetch an archive or patch, or feed one to an unpacker:
# a curl of the pull request API for its labels or title is metadata, not content.
DOWNLOAD = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)
ARCHIVE = re.compile(r"tarball|zipball|/archive/|\.(?:tar(?:\.gz)?|tgz|zip|diff|patch)\b"
                     r"|\|\s*(?:tar|unzip|git\s+apply|git\s+am|patch|sh|bash)\b", re.IGNORECASE)
# Job conditions and steps that check who wrote a comment command.
COMMENTER_CHECK = re.compile(r"author_association|\buser\s*\.\s*login\b|\bgithub\s*\.\s*(?:triggering_)?actor\b",
                             re.IGNORECASE)
PERMISSION_LOOKUP = re.compile(r"getCollaboratorPermissionLevel|collaborators/[^\s'\"]+/permission|checkCollaborator",
                               re.IGNORECASE)
# Inputs of slash-command actions that reject commenters below a permission level.
PERMISSION_INPUTS = {"permission", "permission-level"}
# Artifacts uploaded by the run that triggered a workflow_run, downloaded by run ID.
RUN_DOWNLOAD = re.compile(r"\bgh\s+run\s+download\b", re.IGNORECASE)
JS_ARTIFACT_DOWNLOAD = re.compile(r"\bdownloadArtifact\s*\(", re.IGNORECASE)


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


def third_party_target(value: str, repository: str | None = None) -> str | None:
    """owner/repo[/path] for code from outside the repository, else None.

    repository (owner/repo) is the repository being analysed, when known: references to
    it by full name and a branch or tag (owner/repo/.github/workflows/x.yml@main) are its
    own code.
    """
    if not isinstance(value, str) or value.startswith((*LOCAL_PREFIXES, "docker://")) or "${{" in value:
        return None
    target = value.split("@", 1)[0].strip().casefold()
    if "/" not in target or target.split("/", 1)[0] in FIRST_PARTY_OWNERS:
        return None
    own = repository.casefold() if repository else None
    ref = value.split("@", 1)[1].strip() if "@" in value else ""
    # A full SHA can name a commit that exists only in a fork (an impostor commit), so
    # only branch and tag references count as the repository's own code.
    if own and (target == own or target.startswith(own + "/")) and not FULL_SHA.fullmatch(ref):
        return None
    return target


@dataclass(frozen=True)
class Mount:
    """What an actions/checkout step put at a workspace path."""
    repository: str | None  # owner/repo of another repository; None for this one
    ref: str


def checkout_mount(step: dict, repository: str | None) -> tuple[str, Mount] | None:
    """(workspace path, Mount) for a checkout with literal inputs, else None."""
    uses = step.get("uses")
    if not isinstance(uses, str) or not uses.casefold().startswith("actions/checkout@"):
        return None
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    values = {key: options.get(key, "") for key in ("repository", "ref", "path")}
    if not all(isinstance(value, str) for value in values.values()):
        return None
    other, path = values["repository"].strip(), values["path"].strip().strip("/")
    if other == "${{ github.repository }}" or (repository and other.casefold() == repository.casefold()):
        other = ""
    # Where the code comes from needs a literal repository and path; the ref is only shown.
    if "${{" in other or "${{" in path:
        return None
    path = safe_relative(path) if path else ""
    if path is None:
        return None
    return path, Mount(other.casefold() or None, values["ref"].strip())


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


# Pull request data looked up while the job runs, after any approval.
PR_API = re.compile(r"\bgh\s+pr\s+view\b|\bgh\s+api\b[^\n]*\bpulls\b|api\.github\.com/repos/[^\s'\"]*/pulls",
                    re.IGNORECASE)
JS_IMMUTABLE = re.compile(r"payload\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*sha|workflow_run\s*\.\s*head_sha)",
                          re.IGNORECASE)
JS_MUTABLE = re.compile(r"payload\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*ref|workflow_run\s*\.\s*head_branch)",
                        re.IGNORECASE)
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
ENV_REF = re.compile(r"\benv\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)")
STEP_OUTPUT_REF = re.compile(r"\bsteps\s*\.\s*([A-Za-z_][\w-]*)\s*\.\s*outputs\s*\.\s*([A-Za-z_][\w-]*)")
NEEDS_OUTPUT_REF = re.compile(r"\bneeds\s*\.\s*([A-Za-z_][\w-]*)\s*\.\s*outputs\s*\.\s*([A-Za-z_][\w-]*)")
INPUT_REF = re.compile(r"\binputs\s*\.\s*([A-Za-z_][\w-]*)")
SHELL_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
# echo "name=value" >> "$GITHUB_OUTPUT" / $GITHUB_ENV
FILE_WRITE = re.compile(r"""([A-Za-z_][\w-]*)=(.*?)["']?\s*>>\s*["']?\$\{?(GITHUB_OUTPUT|GITHUB_ENV)\}?""")
SET_OUTPUT = re.compile(r"""setOutput\(\s*['"]([\w-]+)['"]\s*,\s*([^)\n]*)\)""")


@dataclass(frozen=True)
class Taint:
    """A value that carries pull request content, and where it came from."""
    source: str
    mutable: bool


def _combine(taints):
    taints = [t for t in taints if t is not None]
    if not taints:
        return None
    return Taint(taints[0].source, any(t.mutable for t in taints))


@dataclass
class Context:
    """What a step can see: environment variables, earlier step outputs, needs outputs and inputs."""
    env: dict = field(default_factory=dict)      # name -> Taint
    outputs: dict = field(default_factory=dict)  # (step id, name), casefolded -> Taint
    needs: dict = field(default_factory=dict)    # (job, name), casefolded -> Taint
    inputs: dict = field(default_factory=dict)   # name, casefolded -> Taint
    mounts: dict = field(default_factory=dict)   # workspace path ("" = root) -> Mount

    def copy(self):
        return Context(dict(self.env), dict(self.outputs), dict(self.needs), dict(self.inputs), dict(self.mounts))

    def env_expression(self, name):
        # Context property names are case-insensitive in expressions.
        return self.env.get(name) or next((t for k, t in self.env.items() if k.casefold() == name.casefold()), None)


def taint_of(value, ctx: Context, shell: bool = False) -> Taint | None:
    """Whether a string carries pull request content, directly or through ctx."""
    if not isinstance(value, str):
        return None
    found = []
    if IMMUTABLE_REF.search(value) or MUTABLE_REF.search(value):
        match = IMMUTABLE_REF.search(value) or MUTABLE_REF.search(value)
        found.append(Taint(match.group(0), bool(MUTABLE_REF.search(value)) and not IMMUTABLE_REF.search(value)))
    for expression in EXPRESSION.findall(value):
        found += [ctx.env_expression(m.group(1)) for m in ENV_REF.finditer(expression)]
        found += [ctx.outputs.get((m.group(1).casefold(), m.group(2).casefold()))
                  for m in STEP_OUTPUT_REF.finditer(expression)]
        found += [ctx.needs.get((m.group(1).casefold(), m.group(2).casefold()))
                  for m in NEEDS_OUTPUT_REF.finditer(expression)]
        found += [ctx.inputs.get(m.group(1).casefold()) for m in INPUT_REF.finditer(expression)]
    if shell:
        without_expressions = EXPRESSION.sub("", value)
        found += [ctx.env.get(m.group(1)) for m in SHELL_VAR.finditer(without_expressions)]
        if PR_API.search(value):
            found.append(Taint("pull request data looked up while the job runs", True))
    return _combine(found)


def _env_taints(env, ctx: Context) -> dict:
    if not isinstance(env, dict):
        return {}
    return {name: taint for name, value in env.items()
            if isinstance(name, str) and (taint := taint_of(value, ctx)) is not None}


def _shown(text: str, taint: Taint) -> str:
    text = " ".join(text.split())
    return text if taint.source in text else f"{text} (from {taint.source})"


def fetch_of(step: dict, ctx: Context | None = None) -> tuple[str, str, bool] | None:
    """(kind, selector, mutable) when the step brings pull request content in."""
    ctx = ctx or Context()
    uses = step.get("uses")
    uses = uses.casefold() if isinstance(uses, str) else ""
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    if uses.startswith("actions/checkout@") or uses == "actions/checkout":
        ref = options.get("ref") if isinstance(options.get("ref"), str) else ""
        repository = options.get("repository") if isinstance(options.get("repository"), str) else ""
        ref_taint, repository_taint = taint_of(ref, ctx), taint_of(repository, ctx)
        if not ref_taint and not repository_taint:
            return None
        if ref_taint:
            return "checkout", _shown(ref, ref_taint), ref_taint.mutable
        # The head repository at its default branch, or at a branch name: both can move.
        return "checkout", _shown(ref or repository, repository_taint), True
    if uses.startswith("dawidd6/action-download-artifact@") or (
            uses.startswith("actions/download-artifact@")
            and any("workflow_run" in text for text in _strings(options))):
        # Compare by action, not version: a ref bump is not a new download.
        return "artifact", step["uses"].split("@", 1)[0], False
    if uses.startswith("actions/github-script@") and isinstance(options.get("script"), str):
        if JS_ARTIFACT_DOWNLOAD.search(options["script"]) and "workflow_run" in options["script"]:
            return "artifact", "github.rest.actions.downloadArtifact", False
    run = step.get("run")
    if isinstance(run, str):
        if SCRIPT_FETCH.search(run):
            line = next(line for line in run.splitlines() if SCRIPT_FETCH.search(line))
            return "script", line.strip(), True
        step_env = " ".join(_strings(step.get("env")))
        for line in run.splitlines():
            if RUN_DOWNLOAD.search(line) and ("workflow_run" in line or "workflow_run" in step_env):
                return "artifact", " ".join(line.split()), False
            if SCRIPT_CHECKOUT.search(line) or (DOWNLOAD.search(line) and ARCHIVE.search(line)):
                taint = taint_of(line, ctx, shell=True)
                if taint:
                    return "script", _shown(line, taint), taint.mutable
    return None


def _record_writes(step: dict, ctx: Context):
    """Outputs and environment variables a step sets for later steps."""
    step_id = step.get("id") if isinstance(step.get("id"), str) else None
    run = step.get("run")
    if isinstance(run, str):
        for line in run.splitlines():
            for name, value, target in FILE_WRITE.findall(line):
                taint = taint_of(value, ctx, shell=True)
                if taint is None:
                    continue
                if target == "GITHUB_ENV":
                    ctx.env[name] = taint
                elif step_id:
                    ctx.outputs[(step_id.casefold(), name.casefold())] = taint
    uses = step.get("uses") if isinstance(step.get("uses"), str) else ""
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    if step_id and uses.casefold().startswith("actions/github-script@") and isinstance(options.get("script"), str):
        for name, value in SET_OUTPUT.findall(options["script"]):
            taint = taint_of(value, ctx)
            if taint is None and (JS_IMMUTABLE.search(value) or JS_MUTABLE.search(value)):
                taint = Taint(value.strip(), bool(JS_MUTABLE.search(value)))
            if taint is not None:
                ctx.outputs[(step_id.casefold(), name.casefold())] = taint


def _ordered_jobs(jobs: dict) -> list:
    """Job names with each job after the jobs it needs (cycles and unknowns at the end)."""
    def needs(job):
        value = job.get("needs") if isinstance(job, dict) else None
        value = [value] if isinstance(value, str) else value if isinstance(value, list) else []
        return [n for n in value if isinstance(n, str) and n in jobs]
    order, done = [], set()
    pending = sorted(jobs)
    while pending:
        ready = [name for name in pending if all(n in done for n in needs(jobs[name]))]
        if not ready:
            ready = pending[:1]
        for name in ready:
            order.append(name)
            done.add(name)
        pending = [name for name in pending if name not in done]
    return order


class LocalCode:
    """Follows local actions and reusable workflows within one snapshot."""

    def __init__(self, snapshot: Snapshot, load_yaml, repository: str | None = None):
        self.snapshot = snapshot
        self.load_yaml = load_yaml
        self.repository = repository
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
            loaded, issue = None, None
            if text is None:
                # Without a reader (for example the historical replay) local code is not followed.
                if self.snapshot.read is not None or path.startswith(".github/workflows/"):
                    issue = f"Local {kind} {path} could not be read."
            else:
                try:
                    document, node = self.load_yaml(text)
                    if isinstance(document, dict):
                        loaded = document, node
                    else:
                        issue = f"Local {kind} {path} is not a mapping."
                except (ValueError, yaml.YAMLError, RecursionError):
                    issue = f"Local {kind} {path} is invalid or exceeds analysis limits."
            self.cache[path] = loaded, issue
        loaded, issue = self.cache[path]
        # Report a failure on every lookup, not only the first. The first lookup often comes from
        # dependencies(), whose issues are discarded, and every job that reaches the file is affected.
        if issue is not None:
            self.issues.append(issue)
        # Unreadable files are dependencies too, so a change to one is still noticed.
        self.touched.add(path)
        return loaded

    def workflow(self, file: str, document: dict, root=None, inputs=None, depth: int = 0,
                 seen: frozenset = frozenset()) -> dict:
        """{job name: (codes, fetches, issues)}, following env, step outputs and job outputs."""
        jobs = document.get("jobs") if isinstance(document.get("jobs"), dict) else {}
        jobs_node = _key(root, "jobs")[1]
        base = Context(inputs=dict(inputs or {}))
        base.env = _env_taints(document.get("env"), base)
        job_outputs, results = {}, {}
        for name in _ordered_jobs(jobs):
            job = jobs[name]
            if not isinstance(job, dict):
                continue
            ctx = base.copy()
            needs = job.get("needs")
            for needed in [needs] if isinstance(needs, str) else needs if isinstance(needs, list) else []:
                if isinstance(needed, str):
                    for output, taint in job_outputs.get(needed.casefold(), {}).items():
                        ctx.needs[(needed.casefold(), output)] = taint
            ctx.env.update(_env_taints(job.get("env"), ctx))
            known = len(self.issues)
            codes, fetches = self.job(file, job, _key(jobs_node, name)[1], depth, seen, ctx)
            outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
            job_outputs[name.casefold()] = {output.casefold(): taint for output, value in outputs.items()
                                            if isinstance(output, str) and (taint := taint_of(value, ctx))}
            results[name] = (codes, fetches, self.issues[known:])
        return results

    def job(self, file: str, job: dict, node=None, depth: int = 0, seen: frozenset = frozenset(),
            ctx: Context | None = None):
        """(codes, fetches) for one job, including code reached through local references.

        ctx is updated with the outputs and environment the job's steps set.
        """
        ctx = ctx if ctx is not None else Context()
        codes, fetches = [], []
        if isinstance(job.get("uses"), str):
            self._uses(job, job["uses"], file, _key(node, "uses")[0], codes, fetches, depth, seen, True, ctx)
        self._steps(file, job.get("steps"), _key(node, "steps")[1], codes, fetches, depth, seen, ctx)
        return codes, fetches

    def _steps(self, file, steps, steps_node, codes, fetches, depth, seen, ctx):
        if not isinstance(steps, list):
            return
        nodes = steps_node.value if isinstance(steps_node, yaml.nodes.SequenceNode) else []
        nodes = nodes if len(nodes) == len(steps) else [None] * len(steps)
        for step, node in zip(steps, nodes):
            if not isinstance(step, dict):
                continue
            step_ctx = ctx.copy()
            step_ctx.env.update(_env_taints(step.get("env"), ctx))
            found = fetch_of(step, step_ctx)
            if found:
                line = _key(node, "uses")[0] or _key(node, "run")[0]
                fetches.append(Fetch(found[0], found[1], found[2], file, line))
            if isinstance(step.get("uses"), str):
                self._uses(step, step["uses"], file, _key(node, "uses")[0], codes, fetches, depth, seen, False,
                           step_ctx)
            mount = checkout_mount(step, self.repository)
            if mount:
                ctx.mounts[mount[0]] = mount[1]
            # Outputs and $GITHUB_ENV writes are visible to later steps.
            _record_writes(step, step_ctx)
            ctx.outputs.update(step_ctx.outputs)
            ctx.env.update({k: v for k, v in step_ctx.env.items() if k not in (step.get("env") or {})})

    def _uses(self, owner, value, file, line, codes, fetches, depth, seen, job_level, ctx):
        if not value.startswith(LOCAL_PREFIXES):
            target = third_party_target(value, self.repository)
            if target:
                codes.append(Code(target, value, file, line))
            return
        if value.startswith("./") and not job_level:
            # ./ is the workspace: an earlier checkout may have put another repository,
            # or this one in a subdirectory, where the action is read from.
            path = value[2:].split("@", 1)[0].strip().strip("/")
            mounted = sorted((p for p in ctx.mounts if not p or path == p or path.startswith(p + "/")),
                             key=len, reverse=True)
            if mounted:
                where, mount = mounted[0], ctx.mounts[mounted[0]]
                rest = path[len(where):].strip("/")
                if mount.repository:
                    target = f"{mount.repository}/{rest}".rstrip("/")
                    shown = f"{target}@{mount.ref}" if mount.ref else f"{target} (default branch)"
                    codes.append(Code(target, shown, file, line))
                    return
                value = "./" + rest
        if depth >= MAX_DEPTH:
            self.issues.append(f"Local references nest deeper than {MAX_DEPTH} levels at {file}.")
            return
        path = value[2:].split("@", 1)[0].strip()
        relative = safe_relative(path) if path else ""
        if relative is None:
            self.issues.append(f"Local reference {value} in {file} is outside the repository.")
            return
        options = owner.get("with") if isinstance(owner.get("with"), dict) else {}
        inputs = {name.casefold(): taint for name, value_ in options.items()
                  if isinstance(name, str) and (taint := taint_of(value_, ctx))}
        if job_level:
            if not LOCAL_WORKFLOW.fullmatch(relative) or relative in seen:
                return
            loaded = self._load(relative, "workflow")
            if loaded is None:
                return
            document, node = loaded
            for called_codes, called_fetches, _ in self.workflow(
                    relative, document, node, inputs, depth + 1, seen | {relative}).values():
                codes.extend(called_codes)
                fetches.extend(called_fetches)
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
                inner = Context(env=dict(ctx.env), inputs=inputs)
                runs_node = _key(node, "runs")[1]
                self._steps(candidate, runs.get("steps"), _key(runs_node, "steps")[1],
                            codes, fetches, depth + 1, seen | {candidate}, inner)
                # The action's declared outputs become the calling step's outputs.
                step_id = owner.get("id") if isinstance(owner.get("id"), str) else None
                declared = document.get("outputs") if isinstance(document.get("outputs"), dict) else {}
                for name, spec in declared.items():
                    taint = taint_of(spec.get("value") if isinstance(spec, dict) else None, inner)
                    if step_id and isinstance(name, str) and taint:
                        ctx.outputs[(step_id.casefold(), name.casefold())] = taint
            return
        if self.snapshot.read is not None:
            self.issues.append(f"Local action {relative or '.'} has no readable action.yml.")

    def dependencies(self, document: dict) -> set[str]:
        """Local files reachable from a workflow's jobs."""
        self.touched = set()
        self.workflow("", document)
        return set(self.touched)


def gate(document: dict, job: dict, triggers: set[str]) -> str | None:
    """How the workflow waits for a person before running, if it does."""
    on = document.get("on")
    if isinstance(on, dict):
        target = on.get("pull_request_target")
        types = target.get("types") if isinstance(target, dict) else None
        if isinstance(types, list) and "labeled" in types:
            return "a label"
    condition = job.get("if") if isinstance(job.get("if"), str) else ""
    if "label" in condition:
        return "a label"
    if job.get("environment"):
        return "environment approval"
    # Anyone who can see a public repository can comment, and a check of the comment's text
    # (contains(github.event.comment.body, '/ok-to-test')) does not limit who. A comment is a
    # gate only when the job, or a job it needs, checks who wrote it.
    if "issue_comment" in triggers and any(_checks_commenter(item) for item in [job, *_needed(document, job)]):
        return "a comment command"
    return None


def _checks_commenter(job: dict) -> bool:
    condition = job.get("if") if isinstance(job.get("if"), str) else ""
    for step in _job_steps(job):
        options = step.get("with") if isinstance(step.get("with"), dict) else {}
        if PERMISSION_INPUTS & set(options) or any(PERMISSION_LOOKUP.search(text) for text in _strings(step)):
            return True
    return bool(COMMENTER_CHECK.search(condition))


def _needed(document: dict, job: dict) -> list:
    jobs = document.get("jobs") if isinstance(document.get("jobs"), dict) else {}
    needs = job.get("needs")
    names = [needs] if isinstance(needs, str) else needs if isinstance(needs, list) else []
    return [jobs[name] for name in names if isinstance(name, str) and isinstance(jobs.get(name), dict)]


def _job_steps(job: dict) -> list:
    steps = job.get("steps")
    return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []
