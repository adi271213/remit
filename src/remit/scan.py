"""Deliberately limited rules over configured capabilities and contexts, per job."""
import copy
import json
import re
from typing import Any
import yaml

from .sources import MAX_FILE, Oversized, Snapshot
from .contexts import compare_contexts
from .conditions import workflow_run_excludes_pull_requests
from .checkouts import Checkout, weakened
from .flows import PRIVILEGED_TRIGGERS, Code, Control, LocalCode, gate
from .expressions import IDENTIFIER
from .yaml_limits import MAX_ALIASES, validate_graph

SCHEMA_VERSION = "0.1"
LEVELS = {"none": 0, "read": 1, "write": 2}
SCOPES = {
    name: {"none", "read", "write"} for name in (
        "actions", "artifact-metadata", "attestations", "checks", "code-quality",
        "contents", "deployments", "discussions", "issues", "packages", "pages",
        "pull-requests", "security-events", "statuses",
    )
}
SCOPES.update({"id-token": {"none", "write"}, "copilot-requests": {"none", "write"},
               "models": {"none", "read"}, "vulnerability-alerts": {"none", "read"}})
# Selected default/base-branch execution boundaries, not a claim that each
# event grants a write token. See docs/RULES.md (WF003) for rationale and limits.
REVIEW_TRIGGERS = {
    "pull_request_target", "workflow_run", "issue_comment", "issues",
    "discussion", "discussion_comment",
}
TOKEN = re.compile(IDENTIFIER)
# GitHub's "restricted" default, the narrowest default a repository or organization
# can configure. Explicit permissions at or below it can never exceed the real default.
MINIMUM_DEFAULT = {**{scope: "none" for scope in SCOPES}, "contents": "read", "packages": "read"}
LIMITATIONS = [
    "Compares supported configured capabilities, not actual runtime access or PR safety.",
    "Does not inspect executed scripts, remote actions/workflows, cloud trust, or environment guards.",
    "Trigger filter changes and secret delivery to individual steps are outside coverage.",
    "Trigger review covers selected event names only: " + ", ".join(sorted(REVIEW_TRIGGERS)) + ".",
    "Runner ownership/inventory and environment secret/protection settings are not observed. Standard runner "
    "labels follow a documented convention list.",
    "Only direct static matrix fields resolve runner/environment expressions; unchanged unresolved selections "
    "compare symbolically under fixed external context.",
    "Runner/environment association comparison covers supported static rows with unchanged individual target "
    "sets; it does not trace secret delivery or runtime reachability.",
]


def error_report(reason: str) -> dict:
    """Report shape for inputs that could not be compared at all."""
    return {"schemaVersion": SCHEMA_VERSION, "base": None, "head": None, "analysis": "error",
            "review": "none", "findings": [], "diagnostics": [{"file": "input", "job": None,
            "side": "comparison", "kind": "error", "reason": reason}], "limitations": LIMITATIONS.copy()}


MINIMUM_DEFAULT_ASSUMPTION = (
    "Jobs that previously used the repository's default token permissions were compared with GitHub's most "
    "restrictive default (contents: read, packages: read); permissions at or below it cannot be increases.")


class StrictLoader(yaml.SafeLoader):
    pass


# YAML 1.1 treats the GitHub key `on` as True. Retain only true/false booleans.
StrictLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for key, resolvers in StrictLoader.yaml_implicit_resolvers.items():
    StrictLoader.yaml_implicit_resolvers[key] = [
        (tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"
    ]
StrictLoader.add_implicit_resolver("tag:yaml.org,2002:bool",
                                   re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise ValueError("YAML merge keys are unsupported.")
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str):
            raise ValueError("Mapping keys must be strings.")
        if key in result:
            raise ValueError("Duplicate mapping key.")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


StrictLoader.add_constructor("tag:yaml.org,2002:map", _mapping)


def parse(text: str) -> dict:
    return _parse(text)[0]


def load_yaml(text: str):
    """Compose and construct one YAML document within the token, alias and graph limits.

    Returns (document, root node). Raises ValueError or yaml.YAMLError.
    """
    if isinstance(text, Oversized) or len(text.encode()) > MAX_FILE:
        raise ValueError("Workflow exceeds byte limit.")
    depth = 0
    count = 0
    aliases = 0
    for token in yaml.scan(text, Loader=StrictLoader):
        count += 1
        if isinstance(token, yaml.tokens.AliasToken):
            aliases += 1
            if aliases > MAX_ALIASES:
                raise ValueError("Too many YAML aliases.")
        if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                              yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
            depth += 1
        if isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken,
                              yaml.tokens.FlowSequenceEndToken)):
            depth -= 1
        if depth > 50 or count > 60000:
            raise ValueError("YAML structure exceeds limits.")
    loader = StrictLoader(text)
    try:
        node = loader.get_single_node()
        validate_graph(node)
        document = loader.construct_document(node) if node is not None else None
    finally:
        loader.dispose()
    return document, node


def _parse(text: str) -> tuple[dict, "Locations"]:
    document, node = load_yaml(text)
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict) or not document["jobs"]:
        raise ValueError("Workflow needs a nonempty jobs mapping.")
    if "on" not in document:
        raise ValueError("Workflow needs an on trigger.")
    if "env" in document and not isinstance(document["env"], dict):
        raise ValueError("Workflow env must be a mapping.")
    for job in document["jobs"].values():
        if not isinstance(job, dict):
            raise ValueError("Job must be a mapping.")
    # Permission declarations are validated per job in compare(), so one unknown
    # scope doesn't hide findings elsewhere in the file.
    return document, Locations(node)


class Locations:
    """1-based source lines for findings, taken from the composed YAML nodes."""

    def __init__(self, root):
        self.root = root
        self.top = _keys(root)
        jobs = self.top.get("jobs", (None, None))[1]
        self.jobs = {name: (line, value) for name, (line, value) in _keys(jobs).items()}
        self.env = self.top.get("env", (None, None))[1]

    def trigger(self, name):
        on_line, value = self.top.get("on", (None, None))
        if isinstance(value, yaml.nodes.MappingNode):
            return _keys(value).get(name, (on_line, None))[0]
        if isinstance(value, yaml.nodes.SequenceNode):
            return next((item.start_mark.line + 1 for item in value.value
                         if isinstance(item, yaml.nodes.ScalarNode) and item.value == name), on_line)
        return on_line

    def job(self, name, *keys):
        """Line of the first of `keys` present in the job, else the job's own line."""
        line, value = self.jobs.get(name, (None, None))
        fields = _keys(value)
        return next((fields[key][0] for key in keys if key in fields), line)

    def permission(self, name, scope):
        """Line of the scope inside the effective permissions block, else the block, else the job."""
        _, value = self.jobs.get(name, (None, None))
        block = _keys(value).get("permissions") or self.top.get("permissions")
        if block is None:
            return self.job(name)
        return _keys(block[1]).get(scope, block)[0]

    def secret(self, name, secret):
        """Line of the first scalar in the job (then workflow env) that references the secret."""
        line, value = self.jobs.get(name, (None, None))
        if secret == "*":
            fields = _keys(value)
            if isinstance(fields.get("secrets", (None, None))[1], yaml.nodes.ScalarNode):
                return fields["secrets"][0]
            pattern = re.compile(r"\bsecrets\b(?!\s*[.\[])", re.IGNORECASE)
        else:
            pattern = re.compile(r"\bsecrets\s*(?:\.\s*" + re.escape(secret) + r"(?![A-Za-z0-9_-])|\[\s*'"
                                 + re.escape(secret) + r"'\s*\])", re.IGNORECASE)
        for root in (value, self.env):
            for node in _scalars(root):
                if "${{" in node.value and pattern.search(node.value):
                    return node.start_mark.line + 1
        return line


def _keys(node) -> dict:
    if not isinstance(node, yaml.nodes.MappingNode):
        return {}
    return {key.value: (key.start_mark.line + 1, value) for key, value in node.value
            if isinstance(key, yaml.nodes.ScalarNode)}


def _scalars(node):
    # The graph was already bounded by validate_graph; `seen` skips shared aliases.
    stack, seen = [node] if node is not None else [], set()
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, yaml.nodes.ScalarNode):
            yield current
        elif isinstance(current, yaml.nodes.SequenceNode):
            stack.extend(reversed(current.value))
        elif isinstance(current, yaml.nodes.MappingNode):
            stack.extend(child for pair in reversed(current.value) for child in reversed(pair))


def permissions(value: Any) -> dict[str, str]:
    if value in ("read-all", "write-all"):
        level = value.removesuffix("-all")
        return {scope: level if level in valid else ("read" if "read" in valid else "none")
                for scope, valid in SCOPES.items()}
    if not isinstance(value, dict):
        raise ValueError("Unsupported permissions declaration.")
    result = {scope: "none" for scope in SCOPES}
    for scope, level in value.items():
        if scope not in SCOPES:
            raise ValueError("Unknown permission scope; supported scope list needs review.")
        if not isinstance(level, str) or level not in SCOPES[scope]:
            raise ValueError("Invalid permission level.")
        result[scope] = level
    return result


def _triggers(doc: dict) -> set[str]:
    value = doc["on"]
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, dict)) and value and all(isinstance(x, str) for x in value):
        return set(value)
    raise ValueError("Unsupported trigger declaration.")


def _expressions(value, _budget=None):
    # YAML aliases let a small document expand to many logical nodes; PyYAML shares
    # the aliased subtree, so bound this walk to keep analysis time finite.
    if _budget is None:
        _budget = [0]
    _budget[0] += 1
    if _budget[0] > 200000:
        raise ValueError("Workflow structure is too large to analyze.")
    if isinstance(value, dict):
        for child in value.values():
            yield from _expressions(child, _budget)
    elif isinstance(value, list):
        for child in value:
            yield from _expressions(child, _budget)
    elif isinstance(value, str):
        start = 0
        while (start := value.find("${{", start)) != -1:
            i = start + 3
            begin = i
            quoted = False
            while i < len(value):
                if value[i] == "'":
                    if quoted and value[i:i+2] == "''":
                        i += 2
                        continue
                    quoted = not quoted
                if not quoted and value[i:i+2] == "}}":
                    yield value[begin:i]
                    start = i + 2
                    break
                i += 1
            else:
                raise ValueError("Unclosed workflow expression.")


def _secret_expression(expression: str) -> tuple[set[str], bool]:
    names = set()
    unknown = False
    i = 0
    while i < len(expression):
        if expression[i] == "'":
            i += 1
            while i < len(expression):
                if expression[i:i+2] == "''":
                    i += 2
                elif expression[i] == "'":
                    i += 1
                    break
                else:
                    i += 1
            continue
        match = TOKEN.match(expression, i)
        if not match:
            i += 1
            continue
        previous = expression[:i].rstrip()
        i = match.end()
        if match.group().lower() != "secrets" or previous.endswith("."):
            continue
        tail = expression[i:]
        dotted = re.match(r"\s*\.\s*(" + IDENTIFIER + r")", tail)
        bracket = re.match(r"\s*\[\s*'(" + IDENTIFIER + r")'\s*\]", tail)
        if dotted or bracket:
            found = dotted or bracket
            names.add(found.group(1).upper())
            i += found.end()
        elif tail.lstrip().startswith(("[", ".")):
            unknown = True
        else:
            names.add("*")
    names.discard("GITHUB_TOKEN")  # Already implicitly available; WF001 covers its scopes.
    return names, unknown


def _privileges(job, scope, secrets) -> list[str]:
    """What third-party code in this job could use: write scopes, OIDC, secrets, environment."""
    granted = [f"{name}: write" for name, level in sorted((scope or {}).items()) if level == "write"]
    names = sorted(secrets)
    if "*" in names:
        granted.append("all secrets")
    elif names:
        granted.append("secrets: " + ", ".join(names))
    environment = job.get("environment")
    if isinstance(environment, dict):
        environment = environment.get("name")
    if isinstance(environment, str):
        granted.append(f"environment: {environment}")
    return granted


def _secret_refs(doc: dict, job: dict) -> tuple[set[str], bool]:
    names = set()
    unknown = False
    # Workflow env is deliberately included as reference evidence, not runtime proof.
    for expression in _expressions([doc.get("env", {}), job]):
        found, dynamic = _secret_expression(expression)
        names |= found
        unknown |= dynamic
    if job.get("secrets") == "inherit":
        names.add("*")
    return names, unknown


def _scope(doc, job, defaults):
    if "permissions" in job:
        return permissions(job["permissions"])
    if "permissions" in doc:
        return permissions(doc["permissions"])
    return defaults


def _uses_default(document: dict, defaults) -> bool:
    """True when some job in the workflow already runs with the inherited default permissions."""
    for job in (document.get("jobs") or {}).values():
        try:
            if isinstance(job, dict) and _scope(document, job, defaults) is None:
                return True
        except ValueError:
            continue
    return False


def _safe_triggers(document: dict) -> set[str]:
    try:
        return _triggers(document)
    except ValueError:
        return set()


def _publishes(document: dict) -> bool:
    """True for a dedicated release workflow: it runs on releases or pushed tags, and
    otherwise only when started by hand. A CI workflow that also runs on tags is not one."""
    found = _safe_triggers(document)
    on = document.get("on")
    push = on.get("push") if isinstance(on, dict) else None
    tags_only = isinstance(push, dict) and bool(push.get("tags")) and not push.get("branches") \
        and not push.get("branches-ignore")
    if "push" in found and not tags_only:
        return False
    return bool(found) and found <= {"release", "push", "workflow_dispatch"} and ("release" in found or tags_only)


def _pin_advice(triggers) -> str:
    """How to check out the approved commit, for the event the job runs on."""
    if "pull_request_target" in triggers:
        return "Check out the approved commit SHA, github.event.pull_request.head.sha."
    if "workflow_run" in triggers:
        return "Check out the commit that triggering run built, github.event.workflow_run.head_sha."
    # issue_comment payloads carry no pull request commit.
    return ("The comment event carries no commit SHA: have the command name the approved commit and check out "
            "exactly that SHA.")


REPOSITORY_NAME = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
AUDIT_RULES = ("WF010", "WF011")
AUDIT_LIMITATION = ("Audit mode reports the current state for WF010 and WF011 only: pull request content reachable "
                    "from pull_request_target, workflow_run and issue_comment jobs.")


def audit(snapshot: Snapshot, defaults=None, *, repository: str | None = None) -> dict:
    """Current-state report: where privileged workflows bring in pull request content."""
    report = compare(Snapshot("empty", {}), snapshot, defaults, repository=repository, _audit=True)
    report.update({"mode": "audit", "base": None, "renames": [], "inheritedComparisons": [], "assumptions": []})
    report["findings"] = [f for f in report["findings"] if f["rule"] in AUDIT_RULES]
    # Keep what can hide an audited finding: unreadable files or triggers, and local code
    # that could not be followed. Unresolved runners or secrets don't affect these rules.
    report["diagnostics"] = [d for d in report["diagnostics"]
                             if d["job"] is None or d.get("area") == "local-code"]
    report["limitations"] = [AUDIT_LIMITATION, *report["limitations"]]
    report["analysis"] = "complete"
    if report["diagnostics"]:
        report["analysis"] = "error" if any(d["kind"] == "error" for d in report["diagnostics"]) else "incomplete"
    report["review"] = "suggested" if report["findings"] else "none"
    return report


def _execution_text(runner: str | None) -> str:
    """What WF010 can say about the content being run, given the step seen running it, if any."""
    if runner is None:
        return ("Remit saw no later script or local action that runs it: check whether the actions "
                "that follow execute or interpret these files, and if they do, move that work to the "
                "pull_request trigger.")
    if runner.startswith("the same script"):
        seen = runner[0].upper() + runner[1:] + " also runs other commands"
    else:
        seen = runner[0].upper() + runner[1:] + " runs after it"
    return (f"{seen}, which can execute pull request files with those permissions and write to the "
            "Actions cache of the branch the workflow runs on, which later trusted runs may restore. "
            "Run pull request code under the pull_request trigger instead.")


def _merge_shared(findings: list) -> list:
    """One finding per change in a shared local action or reusable workflow, listing every job it reaches.

    A change inside, say, .github/actions/setup is otherwise reported once per job that uses it.
    """
    merged, order = {}, []
    for item in findings:
        if "workflow" not in item or item["job"] is None:
            order.append(item)
            continue
        key = (item["rule"], item["file"], item["line"], json.dumps(item["after"], sort_keys=True))
        if key not in merged:
            merged[key] = {**item, "jobs": [{"workflow": item["workflow"], "job": item["job"]}]}
            order.append(merged[key])
            continue
        entry = {"workflow": item["workflow"], "job": item["job"]}
        if entry not in merged[key]["jobs"]:
            merged[key]["jobs"].append(entry)
    for item in merged.values():
        names = list(dict.fromkeys(entry["job"] for entry in item["jobs"]))
        if len(item["jobs"]) == 1:
            del item["jobs"]
        elif item["message"].startswith(f"Job {item['job']} "):
            rest = item["message"][len(f"Job {item['job']} "):]
            if len(names) == 1:
                workflows = len({entry["workflow"] for entry in item["jobs"]})
                item["message"] = f"Job {names[0]}, in each of {workflows} workflows, " + rest
            else:
                listed = ", ".join(names[:-1]) + f" and {names[-1]}"
                item["message"] = f"Each of jobs {listed} " + rest
    return order


def compare(base: Snapshot, head: Snapshot, defaults=None, *, repository: str | None = None,
            _audit=False) -> dict:
    """Privilege changes from base to head.

    repository is the analysed repository's owner/repo, when known, so that references to it
    by full name are treated as its own code rather than third-party code.
    """
    report = {"schemaVersion": SCHEMA_VERSION, "base": base.identity, "head": head.identity,
              "analysis": "complete", "review": "none", "findings": [], "diagnostics": [],
              "renames": [], "examinedFiles": [], "limitations": LIMITATIONS.copy(),
              "defaultPermissions": defaults, "inheritedComparisons": [],
              "assumptions": []}

    def diagnostic(path, side, reason, *, job=None, error=False, area=None):
        item = {"file": path, "side": side, "job": job, "kind": "error" if error else "incomplete", "reason": reason}
        if area:
            item["area"] = area
        report["diagnostics"].append(item)

    def finding(rule, path, job, before, after, message, line=None, workflow=None):
        item = {"rule": rule, "file": path, "job": job, "line": line,
                "before": before, "after": after, "message": message}
        if workflow is not None and workflow != path:
            item["workflow"] = workflow  # the finding sits in a local action or reusable workflow
        report["findings"].append(item)

    if defaults is not None:
        defaults = permissions(defaults)
        report["defaultPermissions"] = defaults
    old_only = set(base.files) - set(head.files)
    new_only = set(head.files) - set(base.files)
    renamed = {}  # new path -> old path, for files renamed without content changes
    for new in sorted(new_only):
        old = next((p for p in sorted(old_only) if base.files[p] == head.files[new]), None)
        if old is not None:
            old_only.remove(old)
            renamed[new] = old
            report["renames"].append({"before": old, "after": new})
    if repository is not None and not REPOSITORY_NAME.fullmatch(repository):
        raise ValueError("Repository name must be owner/repo.")
    # Most files are identical on both sides, so each distinct text is parsed once. Parsed
    # documents are only read, never modified, so the two sides can share them.
    memo = {}

    def cached(function):
        def call(text):
            key = (function, text)
            if key not in memo:
                try:
                    memo[key] = (True, function(text))
                except (ValueError, yaml.YAMLError, RecursionError) as exc:
                    memo[key] = (False, exc)
            ok, value = memo[key]
            if not ok:
                raise value
            return value
        return call
    parse = cached(_parse)
    base_local = LocalCode(base, cached(load_yaml), repository)
    head_local = LocalCode(head, cached(load_yaml), repository)

    def local_code_changed(path):
        """True when an unchanged workflow reaches local code that changed.

        Only called when the workflow's text is the same on both sides. If every file the
        base side reaches is also unchanged, the head side reaches exactly the same files,
        so walking the base side is enough: the first changed file on any path is found there.
        """
        text = base_local.text(path)
        if text is None:
            return False
        try:
            paths = base_local.dependencies(parse(text)[0])
        except (ValueError, yaml.YAMLError, RecursionError):
            return False
        return any(base_local.text(dep) != head_local.text(dep) for dep in paths)

    for path in sorted(head.files):
        # A renamed workflow is compared with its old self: quiet unless the local code it
        # reaches changed.
        base_path = renamed.get(path, path)
        if base.files.get(base_path) == head.files[path] and not local_code_changed(base_path):
            continue
        report["examinedFiles"].append(path)
        documents = {}
        nodes = {"base": None, "head": None}
        lines = None
        for side, text in (("base", base.files.get(base_path)), ("head", head.files[path])):
            if text is None:
                documents[side] = {"on": [], "jobs": {}}
                continue
            if isinstance(text, Oversized):
                diagnostic(path, side, f"Workflow is larger than the {MAX_FILE // (1024 * 1024)} MiB analysis "
                                       "limit and was not read.")
                continue
            try:
                documents[side], located = parse(text)
                nodes[side] = located
                if side == "head":
                    lines = located
            except (ValueError, yaml.YAMLError, RecursionError) as exc:
                # PyYAML exception strings include source lines; never echo them.
                safe = isinstance(exc, ValueError) and not isinstance(exc, yaml.YAMLError)
                reason = str(exc) if safe else "Invalid YAML or unsupported YAML structure."
                diagnostic(path, side, reason, error=True)
        if len(documents) != 2:
            continue
        before, after = documents["base"], documents["head"]
        # Whole-workflow walks: jobs in dependency order, so needs outputs carry across.
        workflow_flows = {
            side: local.workflow(path, documents[side], nodes[side].root if nodes[side] else None)
            for side, local in (("base", base_local), ("head", head_local))}
        try:
            old_triggers = _triggers(before) if base.files.get(base_path) is not None else set()
            new_triggers = _triggers(after)
            for trigger in sorted((new_triggers - old_triggers) & REVIEW_TRIGGERS):
                finding("WF003", path, None, None, trigger,
                        f"Review-sensitive trigger {trigger} introduced. "
                        "Review who can invoke it and token/secret access.",
                        lines.trigger(trigger))
        except ValueError as exc:
            diagnostic(path, "comparison", str(exc), error=True)
        for name, new_job in sorted(after["jobs"].items()):
            old_job = before["jobs"].get(name)
            changes, issues, assumptions = compare_contexts(old_job, new_job)
            context_keys = {"WF005": ("runs-on",), "WF007": ("environment",), "WF008": ("environment", "strategy")}
            for change in changes:
                finding(change["rule"], path, name, change["before"], change["after"], change["message"],
                        lines.job(name, *context_keys[change["rule"]]))
            for kind, reason in issues:
                diagnostic(path, "comparison", reason, job=name, error=kind == "error")
            for assumption in assumptions:
                if assumption not in report["assumptions"]:
                    report["assumptions"].append(assumption)
            values = {}
            for side, doc, job in (("base", before, old_job), ("head", after, new_job)):
                try:
                    values[side] = permissions({}) if job is None else _scope(doc, job, defaults)
                except ValueError as exc:
                    diagnostic(path, side, str(exc), job=name, error=True)
            old_value, new_value = values.get("base"), values.get("head")
            if len(values) != 2:
                pass  # The failing side already has an error diagnostic.
            elif old_value is None and new_value is None:
                # The same existing job inherits the same external setting on both
                # sides: D -> D is equal for every fixed possible default map D.
                report["inheritedComparisons"].append({"file": path, "job": name})
            elif new_value is None:
                # Explicit (or absent) -> inherited default. The default is not visible,
                # so report the switch itself unless the old map was already maximal. A new
                # job in a workflow whose jobs already used the default changes nothing.
                if old_job is None and _uses_default(before, defaults):
                    pass
                elif any(LEVELS[old_value[scope]] < max(LEVELS[x] for x in SCOPES[scope]) for scope in SCOPES):
                    granted = {scope: level for scope, level in old_value.items() if level != "none"}
                    finding("WF002", path, name, None if old_job is None else (granted or "none"),
                            "repository default",
                            f"{'New job' if old_job is None else 'Job'} {name} uses the repository's default token "
                            "permissions, which this analysis cannot see. Declare permissions explicitly or supply "
                            "default-permissions.", lines.job(name))
            elif old_value is None:
                # Inherited -> explicit. Only levels above the narrowest possible default
                # can be increases; usually this is a hardening change and stays quiet.
                # Read access is reported nowhere else for a declared block either: declaring
                # read scopes is hardening, so only write scopes can be increases here.
                above = {scope: level for scope, level in sorted(new_value.items())
                         if LEVELS[level] > LEVELS[MINIMUM_DEFAULT[scope]] and level == "write"}
                if MINIMUM_DEFAULT_ASSUMPTION not in report["assumptions"]:
                    report["assumptions"].append(MINIMUM_DEFAULT_ASSUMPTION)
                if above:
                    scopes = ", ".join(f"{scope}: {level}" for scope, level in above.items())
                    finding("WF002", path, name, "repository default", above,
                            f"Job {name} replaces the repository's default token permissions with {scopes}, which "
                            "may exceed that default. Confirm the job needs them.",
                            lines.permission(name, next(iter(above))))
            else:
                for scope in sorted(SCOPES):
                    old, new = old_value[scope], new_value[scope]
                    # A new job that declares read access is narrower than any default
                    # token, so only its write scopes (and id-token) are increases.
                    if LEVELS[new] > LEVELS[old] and not (old_job is None and new == "read"):
                        capability = "request an OIDC identity token" if scope == "id-token" else f"use {scope}: {new}"
                        finding("WF001", path, name, {scope: old}, {scope: new},
                                f"Job {name} is newly configured to {capability}. Runtime access is not verified.",
                                lines.permission(name, scope))
            refs = {}
            for side, doc, job in (("base", before, old_job), ("head", after, new_job)):
                try:
                    refs[side] = (set(), False) if job is None else _secret_refs(doc, job)
                    if refs[side][1]:
                        diagnostic(path, side, "Dynamic secret selection cannot be resolved.", job=name)
                except ValueError as exc:
                    diagnostic(path, side, str(exc), job=name, error=True)
            # An unresolved head selector does not erase known new literal
            # references. An unresolved base could already name any head secret,
            # so no addition can be established from that comparison.
            if len(refs) == 2 and not refs["base"][1]:
                old, new = refs["base"][0], refs["head"][0]
                added = set() if "*" in old else ({"*"} if "*" in new else new - old)
                for secret in sorted(added):
                    display = "all available secrets" if secret == "*" else secret
                    finding("WF004", path, name, None, display,
                            f"Job {name} adds a reference or forwarding path to {display}. "
                            "Availability and actual access are not verified.",
                            lines.secret(name, secret))
            # Code the job runs, followed into local actions and reusable workflows.
            flows = {}
            for side, job in (("base", old_job), ("head", new_job)):
                codes, fetches, issues = workflow_flows[side].get(name, ([], [], [])) if job else ([], [], [])
                flows[side] = (codes, fetches)
                for reason in dict.fromkeys(issues):
                    diagnostic(path, side, reason, job=name, area="local-code")
            if "head" not in refs:
                continue
            # Invalid permissions were reported above; the code-flow rules still run.
            unreadable_permissions = "head" not in values
            granted = _privileges(new_job, new_value, refs["head"][0])

            controls = {side: [c for c in flows[side][0] if isinstance(c, Control)] for side in flows}
            third_party = {side: [c for c in flows[side][0] if isinstance(c, Code)] for side in flows}

            # WF012: a job holding write access, OIDC, secrets or an environment, or one in a
            # release workflow, newly restores files from the Actions cache, which other runs
            # of the branch can write.
            stakes = list(granted)
            if not stakes and _publishes(after):
                stakes = ["release" if "release" in _safe_triggers(after) else "tag pushes"]
            old_caches = {c.key for c in controls["base"] if c.kind == "cache"}
            reported = set()
            for control in controls["head"]:
                if stakes and control.kind == "cache" and control.key not in old_caches \
                        and control.key not in reported:
                    reported.add(control.key)
                    via = f" through {control.file}" if control.file != path else ""
                    finding("WF012", control.file, name, None, {"cache": control.detail, "privileges": stakes},
                            f"Job {name} now restores files from the Actions cache ({control.detail}){via} "
                            + (f"while it has {'; '.join(granted)}" if granted else
                               f"in a workflow that runs on {stakes[0]}")
                            + ". Any run that can write this branch's cache, including "
                            "pull request code in a pull_request_target, workflow_run or issue_comment job, can "
                            "plant files this job then uses. Don't restore caches in jobs that publish, deploy "
                            "or hold secrets.", control.line, workflow=path)

            # WF013: a checkout drops persist-credentials: false where the token is worth taking.
            token_matters = new_value is None or any(level == "write" for level in (new_value or {}).values())
            # Each checkout is matched to the same step on the base side before its setting is
            # compared, so an added or deleted checkout cannot stand in for one that changed.
            checkouts = {side: [c for c in flows[side][0] if isinstance(c, Checkout)] for side in flows}
            for control, certain in weakened(checkouts["base"], checkouts["head"]):
                custom = control.detail.endswith("with a custom token")
                if not (token_matters or custom):
                    continue
                uses = control.detail.removesuffix(" with a custom token")
                major = uses.rsplit("@v", 1)[1].split(".")[0] if "@v" in uses else ""
                where = ("in a file outside the workspace, where later steps can still read it"
                         if major.isdigit() and int(major) >= 6 else
                         "in the repository's .git/config, where later steps can read it and a workspace "
                         "upload can publish it")
                token = "the custom token" if custom else "the job's token"
                if certain:
                    after_value = {"persist-credentials": True}
                    change = f"Job {name}'s checkout ({uses}) no longer sets persist-credentials: false"
                else:
                    # The steps could not be told apart: one was moved, rewritten or given a new
                    # id, or a safe copy was added beside it.
                    after_value = {"persist-credentials": True, "match": "ambiguous"}
                    change = (f"Job {name}'s checkouts of this repository and path changed, and this one ({uses}) "
                              "does not set persist-credentials: false where one did before")
                finding("WF013", control.file, name, {"persist-credentials": False}, after_value,
                        f"{change}, so {token} is kept {where}. Restore persist-credentials: false unless a "
                        "later step pushes with it.", control.line, workflow=path)

            # WF009: third-party code newly running where it can use the job's privileges.
            old_targets = {code.target for code in third_party["base"]}
            reported = set()
            for code in sorted(third_party["head"], key=lambda c: c.target):
                if granted and code.target not in old_targets and code.target not in reported:
                    reported.add(code.target)
                    via = f" through {code.file}" if code.file != path else ""
                    finding("WF009", code.file, name, None, {"uses": code.uses, "privileges": granted},
                            f"Job {name} now runs third-party code from {code.uses}{via}, which can use "
                            f"{'; '.join(granted)}. Review the action and pin it to a full commit SHA.",
                            code.line, workflow=path)

            # WF010 / WF011: pull request content brought into a privileged workflow.
            def privileged(document, exists, job_name=name):
                try:
                    found = set(_triggers(document)) & set(PRIVILEGED_TRIGGERS) if exists else set()
                except ValueError:
                    return set()
                # A workflow_run job whose condition (or a needed job's) rules out runs caused by
                # pull requests never receives pull request content through that trigger.
                if "workflow_run" in found and workflow_run_excludes_pull_requests(document, job_name):
                    found.discard("workflow_run")
                return found
            head_triggers = privileged(after, True)
            if not head_triggers:
                continue
            base_triggers = privileged(before, base.files.get(base_path) is not None and old_job is not None)
            head_gate = gate(after, new_job, head_triggers)
            base_gate = gate(before, old_job, base_triggers) if old_job is not None else None

            def keyed(fetch, gate_):
                rule = "WF011" if fetch.mutable and gate_ else "WF010"
                return rule, fetch.kind, " ".join(fetch.ref.split()).casefold(), fetch.file
            old_keys = {keyed(f, base_gate) for f in flows["base"][1]} if base_triggers else set()
            capabilities = list(granted)
            if unreadable_permissions:
                capabilities.append("token permissions that could not be read")
            elif new_value is None:
                capabilities.append("the repository's default token permissions")
            capability_text = "; ".join(capabilities) or "a read-only token"
            trigger_text = ", ".join(sorted(head_triggers))
            seen = set()
            for fetch in flows["head"][1]:
                key = keyed(fetch, head_gate)
                if key in old_keys or key in seen:
                    continue
                seen.add(key)
                after_value = {"kind": fetch.kind, "ref": fetch.ref, "triggers": sorted(head_triggers),
                               "privileges": capabilities}
                via = f" through {fetch.file}" if fetch.file != path else ""
                if key[0] == "WF011":
                    finding("WF011", fetch.file, name, None, {**after_value, "gate": head_gate},
                            f"Job {name} waits for {head_gate} and then checks out a mutable pull request "
                            f"reference ({fetch.ref}){via}. The author can push new commits after approval and "
                            f"before checkout (time-of-check to time-of-use). {_pin_advice(head_triggers)}",
                            fetch.line, workflow=path)
                else:
                    if fetch.runner:
                        after_value["runBy"] = fetch.runner
                    finding("WF010", fetch.file, name, None, after_value,
                            f"Job {name} runs on {trigger_text} and {'' if _audit else 'now '}brings in pull "
                            f"request content ({fetch.ref}){via}. The job has {capability_text}. "
                            + _execution_text(fetch.runner), fetch.line, workflow=path)
    report["findings"] = _merge_shared(report["findings"])
    if report["inheritedComparisons"]:
        report["assumptions"].append(
            "Unchanged inherited permissions for matched job IDs compare symbolically, assuming external "
            "repository/organization defaults stay fixed. Their values and runtime restrictions are not observed.")
    if report["diagnostics"]:
        report["analysis"] = "error" if any(d["kind"] == "error" for d in report["diagnostics"]) else "incomplete"
    if report["findings"]:
        report["review"] = "suggested"
    return report
