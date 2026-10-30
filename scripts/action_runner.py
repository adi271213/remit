"""Stdlib-only Action controller: publish explicit outcomes even if setup fails."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_KEYS = ("analysis-status", "review-status", "finding-count", "analysis-exit-code",
               "report-path", "summary-path", "base-sha", "head-sha")


def bootstrap(root, folder):
    # Only files from the pinned Action checkout are imported by the child.
    # No venv, package installer, optional binary extension, or network is needed.
    try:
        if sys.version_info < (3, 11):
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
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as exc:
        raise OSError("Bundled dependency verification failed.") from exc
    return Path(sys.executable)


def execute(root, folder):
    python = bootstrap(root, folder)
    env = {**os.environ, "PRIVILEGE_REPORT": str(folder / "report.json"),
           "PRIVILEGE_SUMMARY": str(folder / "summary.md")}
    return subprocess.run([str(python), "-I", str(root / "scripts/action_entry.py")],
                          env=env, timeout=90).returncode


def error_report(reason):
    return {"schemaVersion": "0.1", "base": None, "head": None,
            "analysis": "error", "review": "none", "findings": [],
            "diagnostics": [{"file": "action", "side": "execution", "job": None,
                             "kind": "error", "reason": reason}],
            "limitations": ["No successful analysis was established. Inspect workflow logs; do not infer PR safety."]}


def run():
    mode = os.environ.get("PRIVILEGE_MODE", "require-complete")
    folder = Path(tempfile.mkdtemp(prefix="workflow-privilege-report.", dir=os.environ.get("RUNNER_TEMP")))
    report_path, summary_path = folder / "report.json", folder / "summary.md"
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
                   str(report_path), str(summary_path), report.get("base") or "", report.get("head") or "")))
    # UUID-style delimiter prevents newline injection through runner paths.
    if target := os.environ.get("GITHUB_OUTPUT"):
        import uuid
        with open(target, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                delimiter = "wpc_" + uuid.uuid4().hex
                handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
    if target := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(summary)
    print("::group::Workflow privilege report")
    print(report_path.read_text(encoding="utf-8"), end="")
    print("::endgroup::")
    if report["analysis"] != "complete":
        print("::warning title=Workflow privilege analysis " + report["analysis"]
              + "::Analysis did not complete. Review the job summary; no clean result was established.")
    elif report["findings"]:
        print("::notice title=Workflow privilege review suggested::Configured capability changes require human review; see the job summary.")
    return 0 if mode == "advisory" else code

if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except OSError:
        print("::error title=Workflow privilege reporting failed::Could not create or publish Action reports.", file=sys.stderr)
        raise SystemExit(2)
