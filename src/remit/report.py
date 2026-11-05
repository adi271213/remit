import html
import json


# Review questions describe checks for a human; they do not assert observed access.
REVIEW_GUIDANCE = {
    "WF001": ("Confirm that this job needs the new token scopes. Check which events can run it and who controls "
              "the code it executes."),
    "WF002": ("Declare the job's permissions explicitly, or confirm that the repository default token permissions "
              "are acceptable for it."),
    "WF003": ("Check who can cause the new event and which revision supplies the executed code. Review token and "
              "secret access."),
    "WF004": ("Confirm why the new secret reference or forwarding path is needed. Review its consumer and the "
              "applicable secret scope."),
    "WF005": ("Confirm the intended runner labels/group, who can schedule work there, and its access to internal "
              "resources."),
    "WF007": ("Check the selected environment's scoped settings and protection rules. A target change can add or "
              "remove access and approval constraints."),
    "WF009": ("Check who maintains the new action or reusable workflow, that it is pinned to a full commit SHA, "
              "and whether the job really needs to give it these privileges."),
    "WF010": ("Check that this job never runs, builds or installs pull request content while it holds secrets or "
              "write access. Move that work to a job triggered by pull_request, and pass results through artifacts "
              "it treats as data."),
    "WF011": ("Make the job check out the exact commit that was approved (a SHA captured at approval time), not a "
              "branch or pull request ref that can move after approval."),
    "WF012": ("Check whether this job publishes, deploys or uses its secrets on files restored from the cache. If "
              "it does, build it from a clean install instead."),
    "WF013": ("Restore persist-credentials: false unless a later step needs the stored token, for example to "
              "push."),
    "WF008": ("Confirm that each newly paired runner should use that environment. Review runner access, "
              "environment-scoped settings and protection rules."),
}
MAX_VALUE_CHARS = 240


def _text(value):
    text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
    # Keep repository-controlled names literal, including Markdown links/images,
    # emphasis and backslashes that could alter the surrounding table.
    return "".join(f"&#{ord(char)};" if char in "\\`*_[]()!|~" else char for char in text)


def _identity(value):
    return f"`{_text(value)}`" if value else "unavailable"


def _value(value):
    """Summarize recorded values without dropping full evidence from the JSON."""
    def plain(item):
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, sort_keys=True)

    if value is None:
        text = "Not recorded"
    elif isinstance(value, dict):
        text = "; ".join(f"{key}: {plain(item)}" for key, item in sorted(value.items()))
    else:
        text = plain(value)
    shortened = len(text) > MAX_VALUE_CHARS
    if shortened:
        text = text[:MAX_VALUE_CHARS] + " … (shortened; see JSON)"
    return _text(text), shortened


def _combine_token_rows(items):
    """Show one WF001 row per job; write-all would otherwise produce a row per scope."""
    grants = [item for item in items if item["rule"] == "WF001"]
    if len(grants) < 2:
        return items
    before = {k: v for item in grants for k, v in item["before"].items()}
    after = {k: v for item in grants for k, v in item["after"].items()}
    oidc = ", including an OIDC identity token" if "id-token" in after else ""
    combined = {**grants[0], "before": before, "after": after,
                "message": f"Job {grants[0]['job']} gains {len(after)} higher token permission scopes{oidc}. "
                           "Runtime access is not verified."}
    rest = [item for item in items if item["rule"] != "WF001"]
    position = items.index(grants[0])
    return rest[:position] + [combined] + rest[position:]


def markdown(report: dict) -> str:
    status = report["analysis"]
    audit = report.get("mode") == "audit"
    if status != "complete":
        title = ("Audit " if audit else "Analysis ") + status
    elif report["findings"]:
        title = "Audit: pull request content reaches privileged workflows" if audit else "Review suggested"
    else:
        title = ("Audit: no pull request content in privileged workflows" if audit
                 else "No supported privilege expansions detected")
    if audit:
        lines = [f"## {title}", "", f"Audited: {_identity(report['head'])}", ""]
    else:
        lines = [f"## {title}", "", f"Base: {_identity(report['base'])}", f"Head: {_identity(report['head'])}", ""]
    # One heading per workflow file, then one table per job (workflow-level first).
    files = {}
    for item in report["findings"]:
        files.setdefault(item["file"], {}).setdefault((item["job"], item.get("workflow")), []).append(item)
    shortened = False
    missing_value = False
    for file, jobs in files.items():
        lines += ["### " + _text(file), ""]
        for (job, workflow), items in jobs.items():
            items = _combine_token_rows(items)
            heading = "Job: " + _text(job) if job is not None else "Workflow-level change"
            if workflow:
                heading += " (in " + _text(workflow) + ")"
            if audit:
                # Nothing to compare against: show where each finding is and what it means.
                lines += [heading, "", "| Rule | Line | Finding |", "|---|---|---|"]
                for item in items:
                    line = str(item["line"]) if isinstance(item.get("line"), int) else "—"
                    lines.append("| " + " | ".join((_text(item["rule"]), line, _text(item["message"]))) + " |")
            else:
                lines += [heading, "", "| Rule | Before | After | Change |", "|---|---|---|---|"]
            for item in [] if audit else items:
                before, short_before = _value(item["before"])
                after, short_after = _value(item["after"])
                shortened |= short_before or short_after
                missing_value |= item["before"] is None or item["after"] is None
                lines.append("| " + " | ".join((_text(item["rule"]), before, after, _text(item["message"]))) + " |")
            lines += ["", "Review:", ""]
            for rule in dict.fromkeys(item["rule"] for item in items):
                guidance = REVIEW_GUIDANCE.get(rule, "Review the configured change and any analysis limitations.")
                lines.append("- " + _text(rule) + ": " + guidance)
            lines.append("")
    if missing_value:
        lines += ["Not recorded means this finding has no value recorded for that side; it does not establish "
                  "whether a runtime resource exists.", ""]
    if shortened:
        lines += ["Long before/after values are shortened in this summary. "
                  "The JSON report retains the full recorded values.", ""]
    if report["diagnostics"]:
        lines += ["### Unresolved analysis", ""]
    for item in report["diagnostics"]:
        lines.append(f"- {_text(item['side'])}: {_text(item['file'])}, "
                     f"job {_text(item['job'] or '—')}: {_text(item['reason'])}")
    if report.get("assumptions"):
        lines += ["", "### Assumptions"]
    for assumption in report.get("assumptions", []):
        lines += ["", "Assumption: " + _text(assumption)]
    if audit:
        lines += ["", "Scope: WF010 and WF011 in the current workflows. "
                      "This report does not establish repository safety."]
    else:
        lines += ["", "Scope: configured capability changes only. This report does not establish PR safety."]
    return "\n".join(lines) + "\n"
