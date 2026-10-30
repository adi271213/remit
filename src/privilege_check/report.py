import html
import json


# Review questions describe checks for a human; they do not assert observed access.
REVIEW_GUIDANCE = {
    "WF001": "Confirm that this job needs the new token scopes. Check which events can run it and who controls the code it executes.",
    "WF003": "Check who can cause the new event and which revision supplies the executed code. Review token and secret access.",
    "WF004": "Confirm why the new secret reference or forwarding path is needed. Review its consumer and the applicable secret scope.",
    "WF005": "Confirm the intended runner labels/group, who can schedule work there, and its access to internal resources.",
    "WF007": "Check the selected environment's scoped settings and protection rules. A target change can add or remove access and approval constraints.",
    "WF008": "Confirm that each newly paired runner should use that environment. Review runner access, environment-scoped settings and protection rules.",
}
MAX_VALUE_CHARS = 240


def _text(value):
    text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
    # Keep repository-controlled names literal, including Markdown links/images,
    # emphasis and backslashes that could alter the surrounding table.
    return "".join(f"&#{ord(char)};" if char in "\\`*_[]()!|~" else char for char in text)


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


def markdown(report: dict) -> str:
    status = report["analysis"]
    if status != "complete":
        title = "Analysis " + status
    elif report["findings"]:
        title = "Review suggested"
    else:
        title = "No supported privilege expansions detected"
    lines = [f"## {title}", "", f"Base: `{_text(report['base'])}`", f"Head: `{_text(report['head'])}`", ""]
    groups = {}
    for item in report["findings"]:
        groups.setdefault((item["file"], item["job"]), []).append(item)
    shortened = False
    missing_value = False
    for (file, job), items in groups.items():
        lines += ["### " + _text(file), "", "Job: " + _text(job) if job is not None else "Workflow-level change", "",
                  "| Rule | Before | After | Change |", "|---|---|---|---|"]
        for item in items:
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
        lines += ["Not recorded means this finding has no value recorded for that side; it does not establish whether a runtime resource exists.", ""]
    if shortened:
        lines += ["Long before/after values are shortened in this summary. The JSON report retains the full recorded values.", ""]
    if report["diagnostics"]:
        lines += ["### Unresolved analysis", ""]
    for item in report["diagnostics"]:
        lines.append(f"- {_text(item['side'])}: {_text(item['file'])}, job {_text(item['job'] or '—')}: {_text(item['reason'])}")
    if report.get("assumptions"):
        lines += ["", "### Assumptions"]
    for assumption in report.get("assumptions", []):
        lines += ["", "Assumption: " + _text(assumption)]
    lines += ["", "Scope: configured capability changes only. This report does not establish PR safety."]
    return "\n".join(lines) + "\n"
