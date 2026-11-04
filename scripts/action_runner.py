"""Stdlib-only Action controller: publish explicit outcomes even if setup fails."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_ANNOTATIONS = 10  # GitHub displays at most 10 warning annotations per step.
OUTPUT_KEYS = ("analysis-status", "review-status", "finding-count", "analysis-exit-code",
               "report-path", "summary-path", "base-sha", "head-sha", "sarif-path")


def bootstrap(root):
    # Only files from the pinned Action checkout are imported by the child.
    # No venv, package installer, optional binary extension, or network is needed.
    try:
        if sys.version_info < (3, 11):  # noqa: UP036 - the runner's python3 may be older than the package floor
            raise ValueError("Python 3.11 required")
        vendor = root / "vendor/pyyaml"
        manifest = json.loads((vendor / "manifest.json").read_text())
        if (manifest["name"], manifest["version"]) != ("PyYAML", "6.0.3"):
            raise ValueError("Unexpected bundled dependency")
        expected = manifest["files"]
        if not isinstance(expected, dict) or not expected:
            raise ValueError("Invalid bundled file manifest")
        actual = {p.relative_to(vendor).as_posix() for p in vendor.rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.name != "manifest.json"}
        if set(expected) != actual:
            raise ValueError("Unexpected vendored files")
        for name, digest in expected.items():
            path = vendor / name
            if path.is_symlink() or not path.resolve().is_relative_to(vendor.resolve()):
                raise ValueError("Invalid vendored path")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("Vendored hash mismatch")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise OSError("Bundled dependency verification failed.") from exc
    return Path(sys.executable)


def execute(root, folder):
    python = bootstrap(root)
    env = {**os.environ, "PRIVILEGE_REPORT": str(folder / "report.json"),
           "PRIVILEGE_SUMMARY": str(folder / "summary.md"), "PRIVILEGE_SARIF": str(folder / "report.sarif")}
    return subprocess.run([str(python), "-I", str(root / "scripts/action_entry.py")],
                          env=env, timeout=90).returncode


def error_report(reason):
    return {"schemaVersion": "0.1", "base": None, "head": None,
            "analysis": "error", "review": "none", "findings": [],
            "diagnostics": [{"file": "action", "side": "execution", "job": None,
                             "kind": "error", "reason": reason}],
            "limitations": ["No successful analysis was established. Inspect workflow logs; do not infer PR safety."]}


def _escape(text, *, prop=False):
    """Escape workflow-command text so repository-controlled values cannot inject commands."""
    text = str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def annotation_path(file):
    """Make a finding path relative to the workspace, where annotations are anchored."""
    repo = Path(os.environ.get("PRIVILEGE_REPOSITORY") or ".").resolve()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
    try:
        return (repo.relative_to(workspace) / file).as_posix()
    except ValueError:
        return file


def annotations(findings):
    """Workflow commands that place each finding on its line in the PR diff."""
    lines = []
    for item in findings[:MAX_ANNOTATIONS]:
        if not isinstance(item.get("file"), str):
            continue
        props = "file=" + _escape(annotation_path(item["file"]), prop=True)
        if isinstance(item.get("line"), int):
            props += ",line=" + str(item["line"])
        props += ",title=" + _escape(f"{item['rule']} review suggested", prop=True)
        lines.append(f"::warning {props}::{_escape(item['message'])}")
    if len(findings) > MAX_ANNOTATIONS:
        lines.append(f"::notice title=More findings::{len(findings) - MAX_ANNOTATIONS} more findings are listed "
                     "in the job summary.")
    return lines


def run():
    mode = os.environ.get("PRIVILEGE_MODE", "require-complete")
    folder = Path(tempfile.mkdtemp(prefix="remit-report.", dir=os.environ.get("RUNNER_TEMP")))
    report_path, summary_path = folder / "report.json", folder / "summary.md"
    sarif_path = folder / "report.sarif"
    fallback = None
    if mode not in ("advisory", "require-complete"):
        fallback = "Invalid Action mode; use advisory or require-complete."
    else:
        try:
            code = execute(ROOT, folder)
        except subprocess.TimeoutExpired:
            fallback = "Action setup or analysis timed out. Inspect workflow logs."
        except (OSError, subprocess.SubprocessError):
            fallback = "Action setup or analysis failed. Inspect workflow logs."
    if fallback is None:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            valid = (report["analysis"] in ("complete", "incomplete", "error")
                     and report["review"] in ("none", "suggested")
                     and isinstance(report["findings"], list)
                     and isinstance(report["diagnostics"], list)
                     and code == (0 if report["analysis"] == "complete" else 2))
            if not valid:
                raise ValueError("inconsistent result")
            summary = summary_path.read_text(encoding="utf-8")
        except (OSError, ValueError, KeyError, TypeError):
            fallback = "The analysis process did not produce a consistent report. Inspect workflow logs."
    if fallback is not None:
        report = error_report(fallback)
        summary = "## Analysis error\n\n" + fallback + "\n\nNo successful analysis was established.\n"
        code = 2
    review = "suggested" if report["findings"] else ("none" if report["analysis"] == "complete" else "unknown")
    # Preserve the scanner report contract; expose uncertainty explicitly in
    # the Action result without changing the core analysis or CLI semantics.
    report["action"] = {"mode": mode, "reviewStatus": review, "analysisExitCode": code}
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary += ("\nAction mode: " + (mode if mode in ("advisory", "require-complete") else "invalid")
                + ". Analysis: " + report["analysis"] + ". Review: " + review
                + ". Analysis exit code: " + str(code) + ".\n"
                "A successful Action step is not approval to merge or evidence that the PR is safe.\n")
    summary_path.write_text(summary, encoding="utf-8")
    outputs = dict(zip(OUTPUT_KEYS, (report["analysis"], review, str(len(report["findings"])), str(code),
                   str(report_path), str(summary_path), report.get("base") or "", report.get("head") or "",
                   str(sarif_path) if fallback is None and sarif_path.is_file() else "")))
    # UUID-style delimiter prevents newline injection through runner paths.
    if target := os.environ.get("GITHUB_OUTPUT"):
        with open(target, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                delimiter = "wpc_" + uuid.uuid4().hex
                handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
    if target := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(summary)
    print("::group::Remit report")
    # Repository-controlled report text must never be interpreted as workflow commands.
    token = "wpc-" + uuid.uuid4().hex
    print(f"::stop-commands::{token}")
    print(report_path.read_text(encoding="utf-8"), end="")
    print(f"::{token}::")
    print("::endgroup::")
    for line in annotations(report["findings"]):
        print(line)
    if report["analysis"] != "complete":
        print("::warning title=Remit analysis " + report["analysis"]
              + "::Analysis did not complete. Review the job summary; no clean result was established.")
    elif report["findings"]:
        print("::notice title=Remit review suggested::Configured capability changes require human "
              "review; see the job summary.")
    return 0 if mode == "advisory" else code


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except OSError:
        print("::error title=Remit reporting failed::Could not create or publish Action reports.",
              file=sys.stderr)
        raise SystemExit(2) from None
