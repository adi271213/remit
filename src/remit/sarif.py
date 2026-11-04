"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers."""
import hashlib
import json

from . import __version__
from .report import REVIEW_GUIDANCE

INFORMATION_URI = "https://github.com/adi271213/remit"
RULES = {
    "WF001": ("token-permission-increase", "A job's token permission scope increases."),
    "WF002": ("default-token-permissions", "A job starts relying on, or replaces, the repository's default token "
                                           "permissions."),
    "WF003": ("review-sensitive-trigger", "A review-sensitive trigger such as pull_request_target is added."),
    "WF004": ("new-secret-reference", "A job newly references a secret or forwards all secrets."),
    "WF005": ("runner-selection-change", "A job's runner changes to a self-hosted, custom, group or unresolved "
                                         "selection."),
    "WF007": ("environment-change", "A job's deployment environment is added, removed or changed."),
    "WF008": ("runner-environment-pairing", "A matrix pairs a runner with a different environment."),
    "WF010": ("pull-request-content-in-privileged-workflow", "A pull_request_target, workflow_run or "
                                                          "issue_comment job newly checks out, runs or downloads "
                                                          "pull request content."),
    "WF011": ("mutable-ref-after-approval", "An approval-gated privileged job checks out a pull request reference "
                                            "that can change after approval (TOCTOU)."),
    "WF009": ("third-party-code-in-privileged-job", "Third-party code newly runs in a job with write scopes, OIDC, "
                                                    "secrets or an environment."),
}


def _fingerprint(finding):
    # Stable across line moves, so code scanning keeps tracking the same alert.
    identity = json.dumps([finding["rule"], finding["file"], finding["job"], finding["after"]], sort_keys=True)
    return hashlib.sha256(identity.encode()).hexdigest()


def sarif(report: dict) -> dict:
    results = []
    for finding in report["findings"]:
        region = {"startLine": finding.get("line") or 1}
        results.append({
            "ruleId": finding["rule"],
            "level": "warning",
            "message": {"text": finding["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["file"]}, "region": region}}],
            "partialFingerprints": {"workflowPrivilegeCheck/v1": _fingerprint(finding)},
            "properties": {"job": finding["job"], "before": finding["before"], "after": finding["after"]},
        })
    notifications = [{
        "level": "error" if item["kind"] == "error" else "warning",
        "message": {"text": f"{item['file']} ({item['side']}"
                            + (f", job {item['job']}" if item["job"] else "") + f"): {item['reason']}"},
    } for item in report["diagnostics"]]
    rules = [{
        "id": rule,
        "name": name,
        "shortDescription": {"text": description},
        "help": {"text": REVIEW_GUIDANCE[rule]},
        "helpUri": f"{INFORMATION_URI}/blob/main/docs/RULES.md",
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "github-actions"]},
    } for rule, (name, description) in RULES.items()]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "remit", "version": __version__,
                                "informationUri": INFORMATION_URI, "rules": rules}},
            "automationDetails": {"id": "remit/"},
            "invocations": [{"executionSuccessful": report["analysis"] == "complete",
                             "toolExecutionNotifications": notifications}],
            "results": results,
            "properties": {"analysis": report["analysis"], "base": report["base"], "head": report["head"]},
        }],
    }
