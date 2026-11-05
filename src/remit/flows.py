"""What code a job runs: third-party actions and fetches of pull request code.

Steps are followed into local composite actions (`uses: ./path`) and local
reusable workflows (`uses: ./.github/workflows/x.yml`), with bounded depth.
GitHub's same-repository form (`uses: $/path`) is followed the same way.
Nothing is executed; files are read through the snapshot's bounded reader.
"""
import bisect
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
class Control:
    """A step whose settings decide what the job trusts or exposes: a cache it restores, or a
    checkout that leaves the token in place for later steps. Carried in the codes list."""
    kind: str    # cache | credentials
    key: str     # what is compared between base and head
    detail: str  # how it is shown
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
    # A later step in the same steps list that can execute what was brought in: a script or
    # a local action, as "a script (line 40)". None when no such step was seen.
    runner: str | None = field(default=None, compare=False)


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
GH_PR_VIEW = re.compile(r"\bgh\s+pr\s+view\b", re.IGNORECASE)
GH_API = re.compile(r"\bgh\s+api\b", re.IGNORECASE)
PULLS = re.compile(r"\bpulls\b", re.IGNORECASE)
API_URL = "api.github.com/repos/"
JS_IMMUTABLE = re.compile(r"payload\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*sha|workflow_run\s*\.\s*head_sha)",
                          re.IGNORECASE)
JS_MUTABLE = re.compile(r"payload\s*\.\s*(?:pull_request\s*\.\s*head\s*\.\s*ref|workflow_run\s*\.\s*head_branch)",
                        re.IGNORECASE)
# The regular expressions below are applied to repository-controlled text, so each scan is
# linear in its input: an attacker's pull request can make a line as long as a workflow file.
ENV_REF = re.compile(r"\benv\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)")
STEP_OUTPUT_REF = re.compile(r"\bsteps\s*\.\s*([A-Za-z_][\w-]*)\s*\.\s*outputs\s*\.\s*([A-Za-z_][\w-]*)")
NEEDS_OUTPUT_REF = re.compile(r"\bneeds\s*\.\s*([A-Za-z_][\w-]*)\s*\.\s*outputs\s*\.\s*([A-Za-z_][\w-]*)")
INPUT_REF = re.compile(r"\binputs\s*\.\s*([A-Za-z_][\w-]*)")
SHELL_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
# The target of echo "name=value" >> "$GITHUB_OUTPUT" / $GITHUB_ENV, matched where a >> starts.
FILE_TARGET = re.compile(r""">>\s*["']?\$\{?(GITHUB_OUTPUT|GITHUB_ENV)\}?""")
NAME_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
SET_OUTPUT = re.compile(r"""setOutput\(\s*['"]([\w-]+)['"]\s*,\s*([^)\n]*)\)""")


@dataclass(frozen=True)
class Taint:
    """A value that carries pull request content, and where it came from."""
    source: str
    mutable: bool


def expressions(text: str) -> list[str]:
    """The contents of each ${{ ... }} in text, as the lazy pattern \\$\\{\\{(.*?)\\}\\} would find them."""
    found, position = [], 0
    while (start := text.find("${{", position)) >= 0:
        end = text.find("}}", start + 3)
        if end < 0:
            break
        found.append(text[start + 3:end])
        position = end + 2
    return found


def without_expressions(text: str) -> str:
    """text with every complete ${{ ... }} removed."""
    parts, position = [], 0
    while (start := text.find("${{", position)) >= 0:
        end = text.find("}}", start + 3)
        if end < 0:
            break
        parts.append(text[position:start])
        position = end + 2
    parts.append(text[position:])
    return "".join(parts)


def pull_request_lookup(text: str) -> bool:
    """gh pr view, gh api ... pulls on one line, or an api.github.com/repos/.../pulls URL."""
    if GH_PR_VIEW.search(text):
        return True
    # gh and api may be split across lines (\s+), but pulls must follow on the line where api ends.
    pulls = [found.start() for found in PULLS.finditer(text)]
    for found in GH_API.finditer(text):
        line_end = text.find("\n", found.end())
        line_end = len(text) if line_end < 0 else line_end
        after = bisect.bisect_left(pulls, found.end())
        if after < len(pulls) and pulls[after] < line_end:
            return True
    lowered = text.casefold()
    for token in re.split(r"[\s'\"]+", lowered):
        index = token.find(API_URL)
        if index >= 0 and "/pulls" in token[index + len(API_URL):]:
            return True
    return False


def file_writes(line: str) -> list[tuple[str, str, str]]:
    """(name, value, GITHUB_OUTPUT | GITHUB_ENV) for each echo "name=value" >> target on a line."""
    writes, segment_start, position = [], 0, 0
    while (arrow := line.find(">>", position)) >= 0:
        target = FILE_TARGET.match(line, arrow)
        if not target:
            position = arrow + 1
            continue
        segment = line[segment_start:arrow]
        equals = -1
        while (equals := segment.find("=", equals + 1)) >= 0:
            start = equals
            while start > 0 and (segment[start - 1].isalnum() or segment[start - 1] in "_-"):
                start -= 1
            first = next((i for i in range(start, equals) if segment[i] in NAME_START), None)
            if first is not None:
                value = segment[equals + 1:].rstrip()
                if value[-1:] in ("'", '"'):
                    value = value[:-1]
                writes.append((segment[first:equals], value, target.group(1)))
                break
        position = segment_start = target.end()
    return writes


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
    for expression in expressions(value):
        found += [ctx.env_expression(m.group(1)) for m in ENV_REF.finditer(expression)]
        found += [ctx.outputs.get((m.group(1).casefold(), m.group(2).casefold()))
                  for m in STEP_OUTPUT_REF.finditer(expression)]
        found += [ctx.needs.get((m.group(1).casefold(), m.group(2).casefold()))
                  for m in NEEDS_OUTPUT_REF.finditer(expression)]
        found += [ctx.inputs.get(m.group(1).casefold()) for m in INPUT_REF.finditer(expression)]
    if shell:
        found += [ctx.env.get(m.group(1)) for m in SHELL_VAR.finditer(without_expressions(value))]
        if pull_request_lookup(value):
            found.append(Taint("pull request data looked up while the job runs", True))
    return _combine(found)


# Expressions whose value never comes from the pull request in the privileged triggers.
TRUSTED_EXPRESSIONS = frozenset({"github.sha", "github.ref", "github.ref_name", "github.base_ref",
                                 "github.event.repository.default_branch",
                                 "github.event.pull_request.base.sha", "github.event.pull_request.base.ref"})


def known_value(value, shell: bool = False) -> bool:
    """True when value is a fixed literal, or built only from trusted expressions.

    A value that refers to anything else (another variable, an input, a command) is unknown:
    replacing a pull request reference with it does not show the reference is gone.
    """
    if isinstance(value, (bool, int, float)):
        return True
    if not isinstance(value, str):
        return False
    if any(" ".join(e.split()).casefold() not in TRUSTED_EXPRESSIONS for e in expressions(value)):
        return False
    rest = without_expressions(value)
    if "${{" in rest:
        return False
    # In a script, $X, ${X}, $(...) and `...` are expanded by the shell.
    return not (shell and ("$" in rest or "`" in rest))


def _apply_env(target: dict, env, ctx: Context, shell: bool = False):
    """Set target's variables from env: a pull request value taints the name, a known value
    replaces (clears) an earlier taint, and an unknown value leaves it as it was."""
    if not isinstance(env, dict):
        return
    for name, value in env.items():
        if not isinstance(name, str):
            continue
        taint = taint_of(value, ctx, shell=shell)
        if taint is not None:
            target[name] = taint
        elif known_value(value, shell=shell):
            target.pop(name, None)


def _env_taints(env, ctx: Context) -> dict:
    found = {}
    _apply_env(found, env, ctx)
    return found


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


# Files that are read, not executed or used as build configuration. Not .txt: requirements.txt
# and CMakeLists.txt are build input.
DOCUMENT = re.compile(r"(?:[\w.-]+/)*(?:[\w.-]+\.(?:md|markdown|rst|adoc)"
                      r"|README|LICENSE|COPYING|NOTICE|AUTHORS|CHANGELOG)", re.IGNORECASE)


def documents_only(step: dict) -> bool:
    """True when a checkout puts only documentation files in the workspace.

    That needs a sparse checkout in non-cone mode listing plain file paths: in cone mode,
    Git always includes every file at the repository root (package.json, Makefile, ...).
    """
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    patterns = options.get("sparse-checkout")
    cone = options.get("sparse-checkout-cone-mode")
    if not isinstance(patterns, str) or not (cone is False or str(cone).strip().lower() == "false"):
        return False
    lines = [line.strip().lstrip("/") for line in patterns.splitlines() if line.strip()]
    return bool(lines) and all(DOCUMENT.fullmatch(line) for line in lines)


# Actions known to read workspace files without executing them. Any other action may
# run what is in the workspace (a README can be a script's input, a config file or a
# template), so its behaviour is treated as unknown.
INERT_ACTIONS = frozenset({"actions/checkout", "actions/upload-artifact"})


def inert(step) -> bool:
    """A later step that cannot execute or interpret what is in the workspace."""
    if not isinstance(step, dict) or "run" in step:
        return False
    uses = step.get("uses")
    if not isinstance(uses, str) or uses.startswith(LOCAL_PREFIXES) or "@" not in uses:
        return False
    return uses.split("@", 1)[0].strip().lower() in INERT_ACTIONS


def _runner(steps, nodes) -> str | None:
    """The first step that can execute workspace files: a script or a local action."""
    for step, node in zip(steps, nodes):
        if not isinstance(step, dict):
            continue
        uses = step.get("uses") if isinstance(step.get("uses"), str) else ""
        if "run" in step:
            line = _key(node, "run")[0]
            return "a script" + (f" (line {line})" if line else "")
        if uses.startswith(LOCAL_PREFIXES):
            line = _key(node, "uses")[0]
            return f"local action {uses}" + (f" (line {line})" if line else "")
    return None


def _major(uses: str) -> int | None:
    """The major version in an action reference such as owner/name@v5.1.0, or None (SHA, branch)."""
    ref = uses.split("@", 1)[1] if "@" in uses else ""
    match = re.fullmatch(r"v?(\d+)(?:\.\d+){0,2}", ref.strip())
    return int(match.group(1)) if match else None


def _off(value) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def _on(value) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def cache_use(step: dict) -> str | None:
    """How a step restores files from the Actions cache, if it does.

    Defaults that depend on the action's version are applied: setup-go caches unless told not
    to from v4, setup-node caches npm from v5 (when package.json names npm as its
    packageManager). A version that can't be read from the reference is not assumed to cache.
    """
    uses = step.get("uses") if isinstance(step.get("uses"), str) else ""
    name = uses.split("@", 1)[0].strip().lower()
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    major = _major(uses)
    if name in ("actions/cache", "actions/cache/restore"):
        return name
    if name in ("actions/setup-node", "actions/setup-python", "actions/setup-java"):
        cache = options.get("cache")
        if isinstance(cache, str) and cache.strip():
            return f"{name} cache: {cache.strip()}"
        if name == "actions/setup-node" and major is not None and major >= 5 \
                and not _off(options.get("package-manager-cache")):
            return f"{name} v{major} automatic npm cache, used when package.json names npm as its packageManager"
        return None
    if name == "actions/setup-go":
        cache = options.get("cache")
        if _on(cache) or (cache is None and major is not None and major >= 4):
            return f"{name} cache" + ("" if cache is not None else f" (on by default in v{major})")
        return None
    if name == "actions/setup-dotnet" and _on(options.get("cache")):
        return f"{name} cache"
    if name == "ruby/setup-ruby" and _on(options.get("bundler-cache")):
        return f"{name} bundler-cache"
    if name == "astral-sh/setup-uv" and _on(options.get("enable-cache")):
        return f"{name} enable-cache"
    if name == "swatinem/rust-cache":
        return name
    if name == "gradle/actions/setup-gradle" and not _on(options.get("cache-disabled")):
        return f"{name} cache"
    return None


def credential_checkout(step: dict) -> tuple[str, bool, int | None] | None:
    """(checkout key, persists credentials, major version) for an actions/checkout step.

    From v2 the token is kept for later Git commands unless persist-credentials is false; a
    value that is an expression may be true.
    """
    uses = step.get("uses") if isinstance(step.get("uses"), str) else ""
    if uses.split("@", 1)[0].strip().lower() != "actions/checkout":
        return None
    options = step.get("with") if isinstance(step.get("with"), dict) else {}
    major = _major(uses)
    key = " ".join(" ".join(str(options.get(name) or "").split()) for name in ("repository", "path"))
    persists = not _off(options.get("persist-credentials")) and (major is None or major >= 2)
    return key, persists, major



# Commands that move or show Git data without executing files from the working tree.
_INERT_COMMANDS = {"git", "gh", "cd", "echo", "printf", "set", "export", "true", "pwd", "ls", "cat"}


def _runs_more(run) -> bool:
    """True when a script that fetches pull request content also runs another kind of command."""
    if not isinstance(run, str):
        return False
    for command in re.split(r"\n|&&|\|\||;", run):
        words = command.strip().split()
        if words and not words[0].startswith("#") and words[0] not in _INERT_COMMANDS:
            return True
    return False


def _record_writes(step: dict, ctx: Context, written: dict):
    """Outputs a step sets (into ctx) and its $GITHUB_ENV writes (into written, a copy of the
    environment later steps will see)."""
    step_id = step.get("id") if isinstance(step.get("id"), str) else None
    run = step.get("run")
    if isinstance(run, str):
        for line in run.splitlines():
            for name, value, target in file_writes(line):
                if target == "GITHUB_ENV":
                    _apply_env(written, {name: value}, ctx, shell=True)
                    continue
                taint = taint_of(value, ctx, shell=True)
                if taint is not None and step_id:
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
            _apply_env(ctx.env, job.get("env"), ctx.copy())
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
        self._steps(file, job.get("steps"), _key(node, "steps")[1], codes, fetches, depth, seen, ctx,
                    job_steps=True)
        return codes, fetches

    def _steps(self, file, steps, steps_node, codes, fetches, depth, seen, ctx, job_steps=False):
        if not isinstance(steps, list):
            return
        nodes = steps_node.value if isinstance(steps_node, yaml.nodes.SequenceNode) else []
        nodes = nodes if len(nodes) == len(steps) else [None] * len(steps)
        for index, (step, node) in enumerate(zip(steps, nodes)):
            if not isinstance(step, dict):
                continue
            step_ctx = ctx.copy()
            _apply_env(step_ctx.env, step.get("env"), ctx)
            found = fetch_of(step, step_ctx)
            # Only a job's own steps are all visible: inside a composite action, the calling
            # job's later steps could still run what was checked out.
            if found and job_steps and found[0] == "checkout" and documents_only(step) \
                    and all(inert(later) for later in steps[index + 1:]):
                found = None
            if found:
                line = _key(node, "uses")[0] or _key(node, "run")[0]
                runner = _runner(steps[index + 1:], nodes[index + 1:])
                if found[0] == "script" and _runs_more(step.get("run")):
                    runner = "the same script" + (f" (line {line})" if line else "")
                fetches.append(Fetch(found[0], found[1], found[2], file, line, runner))
            if isinstance(step.get("uses"), str):
                uses_line = _key(node, "uses")[0]
                cache = cache_use(step)
                if cache:
                    codes.append(Control("cache", cache.split()[0].casefold(), cache, file, uses_line))
                checkout = credential_checkout(step)
                if checkout:
                    key, persists, major = checkout
                    token = (step.get("with") or {}).get("token") if isinstance(step.get("with"), dict) else None
                    shown = f"{step['uses'].strip()}" + (" with a custom token" if isinstance(token, str) else "")
                    codes.append(Control("credentials", f"{file}|{key}|{'persists' if persists else 'off'}",
                                         shown, file, uses_line))
                self._uses(step, step["uses"], file, uses_line, codes, fetches, depth, seen, False,
                           step_ctx)
            mount = checkout_mount(step, self.repository)
            if mount:
                ctx.mounts[mount[0]] = mount[1]
            # Outputs and $GITHUB_ENV writes are visible to later steps.
            # A step's own env: applies to that step only; its $GITHUB_ENV writes reach later steps.
            _record_writes(step, step_ctx, ctx.env)
            ctx.outputs.update(step_ctx.outputs)

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
