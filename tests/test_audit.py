"""`remit audit`: WF010/WF011 in the current state of a repository."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit.cli import main
from remit.report import markdown
from remit.sarif import sarif
from remit.scan import audit
from remit.sources import directory

GATED = """on:
  pull_request_target:
    types: [labeled]
jobs:
  test:
    if: contains(github.event.pull_request.labels.*.name, 'safe to test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: make test
"""
TARGET = """on: pull_request_target
permissions: {contents: write}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/build
"""
COMPOSITE = """runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.sha }}
"""
# Privileged and noisy by other rules' standards, but it never runs pull request content.
ORDINARY = """on: pull_request
permissions: {contents: write, id-token: write}
jobs:
  ci:
    runs-on: [self-hosted, gpu]
    environment: ${{ vars.TARGET }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someone/tool@v1
        with: {token: "${{ secrets[inputs.name] }}"}
"""


def tree(root, files):
    (root / ".github/workflows").mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    return root


def run_cli(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["audit", *args])
    return code, out.getvalue()


class AuditEngine(unittest.TestCase):
    def audit(self, files):
        with tempfile.TemporaryDirectory() as temp:
            return audit(directory(tree(Path(temp), files)))

    def test_reports_existing_toctou_and_pwn_request_through_local_code(self):
        report = self.audit({".github/workflows/test.yml": GATED, ".github/workflows/build.yml": TARGET,
                             ".github/actions/build/action.yml": COMPOSITE})
        self.assertEqual((report["mode"], report["analysis"], report["review"]), ("audit", "complete", "suggested"))
        self.assertEqual(sorted((f["rule"], f["file"], f["line"]) for f in report["findings"]),
                         [("WF010", ".github/actions/build/action.yml", 4), ("WF011", ".github/workflows/test.yml", 9)])
        self.assertIsNone(report["base"])
        self.assertNotIn(" now ", " ".join(f["message"] for f in report["findings"]))

    def test_other_rules_and_unrelated_uncertainty_stay_out_of_an_audit(self):
        report = self.audit({".github/workflows/ci.yml": ORDINARY})
        self.assertEqual((report["analysis"], report["review"], report["findings"]), ("complete", "none", []))
        self.assertEqual(report["diagnostics"], [])

    def test_unfollowable_local_code_and_invalid_workflows_are_not_clean(self):
        missing = self.audit({".github/workflows/build.yml": TARGET})
        self.assertEqual(missing["analysis"], "incomplete")
        self.assertEqual(missing["diagnostics"][0]["area"], "local-code")
        broken = self.audit({".github/workflows/x.yml": "on: [push\n"})
        self.assertEqual(broken["analysis"], "error")

    def test_empty_repository_is_a_complete_clean_audit(self):
        report = self.audit({})
        self.assertEqual((report["analysis"], report["review"], report["examinedFiles"]), ("complete", "none", []))

    def test_markdown_and_sarif_present_an_audit(self):
        report = self.audit({".github/workflows/test.yml": GATED})
        text = markdown(report)
        self.assertTrue(text.startswith("## Audit: pull request content reaches privileged workflows"))
        self.assertIn("| Rule | Line | Finding |", text)
        self.assertIn("| WF011 | 9 |", text)
        self.assertNotIn("Before", text)
        log = sarif(report)
        self.assertEqual(log["runs"][0]["automationDetails"]["id"], "remit-audit/")
        self.assertEqual(log["runs"][0]["results"][0]["ruleId"], "WF011")


class AuditCommand(unittest.TestCase):
    def test_exit_codes_for_clean_findings_fail_on_findings_and_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            clean = tree(Path(temp, "clean"), {".github/workflows/ci.yml": ORDINARY})
            risky = tree(Path(temp, "risky"), {".github/workflows/test.yml": GATED})
            broken = tree(Path(temp, "broken"), {".github/workflows/x.yml": "on: [push\n"})
            self.assertEqual(run_cli("--dir", str(clean), "--fail-on-findings")[0], 0)
            self.assertEqual(run_cli("--dir", str(risky))[0], 0)
            self.assertEqual(run_cli("--dir", str(risky), "--fail-on-findings")[0], 1)
            self.assertEqual(run_cli("--dir", str(broken), "--fail-on-findings")[0], 2)
            code, out = run_cli("--dir", str(Path(temp, "missing")))
            self.assertEqual((code, json.loads(out)["analysis"], json.loads(out)["mode"]), (2, "error", "audit"))

    def test_directory_audit_executes_nothing_and_uses_no_network(self):
        with tempfile.TemporaryDirectory() as temp:
            risky = tree(Path(temp), {".github/workflows/test.yml": GATED,
                                      ".github/workflows/build.yml": TARGET,
                                      ".github/actions/build/action.yml": COMPOSITE})
            with patch("socket.socket", side_effect=AssertionError("network")), \
                    patch("subprocess.run", side_effect=AssertionError("executed")):
                code, out = run_cli("--dir", str(risky))
        self.assertEqual((code, len(json.loads(out)["findings"])), (0, 2))

    def test_ref_is_only_valid_with_repo(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["audit", "--dir", ".", "--ref", "HEAD"])

    def test_git_audit_reads_the_requested_commit_without_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                               stderr=subprocess.DEVNULL).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            tree(repo, {".github/workflows/test.yml": GATED})
            git("add", ".")
            git("commit", "-qm", "vulnerable")
            vulnerable = git("rev-parse", "HEAD")
            (repo / ".github/workflows/test.yml").write_text(GATED.replace("head.ref", "head.sha"))
            git("commit", "-qam", "pin to sha")
            # Working tree changes are ignored: only committed objects are read.
            (repo / ".github/workflows/test.yml").write_text("garbage: [")
            head = json.loads(run_cli("--repo", str(repo))[1])
            old = json.loads(run_cli("--repo", str(repo), "--ref", vulnerable)[1])
        self.assertEqual([f["rule"] for f in head["findings"]], ["WF010"])
        self.assertEqual([f["rule"] for f in old["findings"]], ["WF011"])
        self.assertEqual(old["head"], vulnerable)

    def test_installed_style_entry_point_runs_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            risky = tree(Path(temp), {".github/workflows/test.yml": GATED})
            env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT / "vendor/pyyaml")])}
            cp = subprocess.run([sys.executable, "-m", "remit", "audit", "--dir", str(risky), "--format", "markdown",
                                 "--fail-on-findings"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn("## Audit: pull request content reaches privileged workflows", cp.stdout)
