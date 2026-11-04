"""Deliberately limited rules over configured capabilities and contexts, per job."""
import copy
import re
from typing import Any
import yaml

from .sources import MAX_FILE, Snapshot
from .contexts import compare_contexts
from .flows import PRIVILEGED_TRIGGERS, LocalCode, gate
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
    if len(text.encode()) > MAX_FILE:
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
    if "permissions" in document:
        permissions(document["permissions"])
    for job in document["jobs"].values():
        if not isinstance(job, dict):
            raise ValueError("Job must be a mapping.")
        if "permissions" in job:
            permissions(job["permissions"])
    return document, Locations(node)


class Locations:
    """1-based source lines for findings, taken from the composed YAML nodes."""

    def __init__(self, root):
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

    def uses(self, name, reference):
        """Line of the job's `uses:` (job-level or step) whose value is `reference`."""
        line, value = self.jobs.get(name, (None, None))
        fields = _keys(value)
        candidates = [fields.get("uses")]
        steps = fields.get("steps", (None, None))[1]
        if isinstance(steps, yaml.nodes.SequenceNode):
            candidates += [_keys(step).get("uses") for step in steps.value]
        for item in candidates:
            if item and isinstance(item[1], yaml.nodes.ScalarNode) and item[1].value == reference:
                return item[0]
        return line

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


AUDIT_RULES = ("WF010", "WF011")
AUDIT_LIMITATION = ("Audit mode reports the current state for WF010 and WF011 only: pull request content reachable "
                    "from pull_request_target, workflow_run and issue_comment jobs.")


def audit(snapshot: Snapshot, defaults=None) -> dict:
    """Current-state report: where privileged workflows bring in pull request content."""
    report = compare(Snapshot("empty", {}), snapshot, defaults, _audit=True)
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


def compare(base: Snapshot, head: Snapshot, defaults=None, *, _audit=False) -> dict:
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
    renamed = set()
    for new in sorted(new_only):
        old = next((p for p in sorted(old_only) if base.files[p] == head.files[new]), None)
        if old is not None:
            old_only.remove(old)
            renamed.add(new)
            report["renames"].append({"before": old, "after": new})
    base_local, head_local = LocalCode(base, load_yaml), LocalCode(head, load_yaml)

    def local_code_changed(path):
        """True when an unchanged workflow reaches local code that changed."""
        paths = set()
        for local in (base_local, head_local):
            text = local.text(path)
            if text is None:
                continue
            try:
                paths |= local.dependencies(_parse(text)[0])
            except (ValueError, yaml.YAMLError, RecursionError):
                continue
        return any(base_local.text(dep) != head_local.text(dep) for dep in paths)

    for path in sorted(head.files):
        if path in renamed:
            continue
        if base.files.get(path) == head.files[path] and not local_code_changed(path):
            continue
        report["examinedFiles"].append(path)
        documents = {}
        nodes = {"base": None, "head": None}
        lines = None
        for side, text in (("base", base.files.get(path)), ("head", head.files[path])):
            if text is None:
                documents[side] = {"on": [], "jobs": {}}
                continue
            try:
                documents[side], located = _parse(text)
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
        try:
            old_triggers = _triggers(before) if base.files.get(path) is not None else set()
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
                # so report the switch itself unless the old map was already maximal.
                if any(LEVELS[old_value[scope]] < max(LEVELS[x] for x in SCOPES[scope]) for scope in SCOPES):
                    granted = {scope: level for scope, level in old_value.items() if level != "none"}
                    finding("WF002", path, name, None if old_job is None else (granted or "none"),
                            "repository default",
                            f"{'New job' if old_job is None else 'Job'} {name} uses the repository's default token "
                            "permissions, which this analysis cannot see. Declare permissions explicitly or supply "
                            "default-permissions.", lines.job(name))
            elif old_value is None:
                # Inherited -> explicit. Only levels above the narrowest possible default
                # can be increases; usually this is a hardening change and stays quiet.
                above = {scope: level for scope, level in sorted(new_value.items())
                         if LEVELS[level] > LEVELS[MINIMUM_DEFAULT[scope]]}
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
                    if LEVELS[new] > LEVELS[old]:
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
            for side, local, job in (("base", base_local, old_job), ("head", head_local, new_job)):
                if job is None:
                    flows[side] = ([], [])
                    continue
                known = len(local.issues)
                job_node = nodes[side].jobs.get(name, (None, None))[1] if nodes[side] else None
                flows[side] = local.job(path, job, job_node)
                for reason in dict.fromkeys(local.issues[known:]):
                    diagnostic(path, side, reason, job=name, area="local-code")
            if "head" not in values or "head" not in refs:
                continue
            granted = _privileges(new_job, new_value, refs["head"][0])

            # WF009: third-party code newly running where it can use the job's privileges.
            old_targets = {code.target for code in flows["base"][0]}
            reported = set()
            for code in sorted(flows["head"][0], key=lambda c: c.target):
                if granted and code.target not in old_targets and code.target not in reported:
                    reported.add(code.target)
                    via = f" through {code.file}" if code.file != path else ""
                    finding("WF009", code.file, name, None, {"uses": code.uses, "privileges": granted},
                            f"Job {name} now runs third-party code from {code.uses}{via}, which can use "
                            f"{'; '.join(granted)}. Review the action and pin it to a full commit SHA.",
                            code.line, workflow=path)

            # WF010 / WF011: pull request content brought into a privileged workflow.
            def privileged(document, exists):
                try:
                    return set(_triggers(document)) & set(PRIVILEGED_TRIGGERS) if exists else set()
                except ValueError:
                    return set()
            head_triggers = privileged(after, True)
            if not head_triggers:
                continue
            base_triggers = privileged(before, base.files.get(path) is not None and old_job is not None)
            head_gate = gate(after, new_job, head_triggers)
            base_gate = gate(before, old_job, base_triggers) if old_job is not None else None

            def keyed(fetch, gate_):
                rule = "WF011" if fetch.mutable and gate_ else "WF010"
                return rule, fetch.kind, " ".join(fetch.ref.split()).casefold(), fetch.file
            old_keys = {keyed(f, base_gate) for f in flows["base"][1]} if base_triggers else set()
            capabilities = list(granted)
            if new_value is None:
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
                            "before checkout (time-of-check to time-of-use). Check out the approved commit SHA, "
                            "such as github.event.pull_request.head.sha.",
                            fetch.line, workflow=path)
                else:
                    finding("WF010", fetch.file, name, None, after_value,
                            f"Job {name} runs on {trigger_text} and {'' if _audit else 'now '}brings in pull "
                            "request content "
                            f"({fetch.ref}){via} where it can use {capability_text}. Code from the pull request "
                            "can act with those privileges; run it in a separate job without secrets or write "
                            "access.", fetch.line, workflow=path)
    if report["inheritedComparisons"]:
        report["assumptions"].append(
            "Unchanged inherited permissions for matched job IDs compare symbolically, assuming external "
            "repository/organization defaults stay fixed. Their values and runtime restrictions are not observed.")
    if report["diagnostics"]:
        report["analysis"] = "error" if any(d["kind"] == "error" for d in report["diagnostics"]) else "incomplete"
    if report["findings"]:
        report["review"] = "suggested"
    return report
