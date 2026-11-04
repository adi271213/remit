"""Regressions for problems found in the independent review."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit.scan import audit, compare
from remit.sources import MAX_EXTRA_FILES, directory

COMPOSITE = "runs:\n  using: composite\n  steps:\n    - run: echo setup\n      shell: bash\n"
PWN_COMPOSITE = COMPOSITE + ("    - uses: actions/checkout@v4\n      with:\n"
                             "        ref: ${{ github.event.pull_request.head.sha }}\n")


def tree(root, files):
    (root / ".github/workflows").mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    return root


def job_using(action, count):
    return "".join(f"  j{i}:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {action}\n" for i in range(count))


class ReadBudget(unittest.TestCase):
    def test_many_references_to_one_local_action_cannot_exhaust_the_budget(self):
        # 30 unchanged workflows x 4 jobs = 120 references to the same action, more than
        # the 100-file budget. A new pull_request_target job and a pwn checkout added to
        # that action must still be reported.
        unchanged = "on: push\npermissions: {}\njobs:\n" + job_using("./.github/actions/setup", 4)
        files = {f".github/workflows/w{i}.yml": unchanged for i in range(30)}
        new = ("on: pull_request_target\npermissions: {contents: read}\njobs:\n"
               "  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/setup\n")
        with tempfile.TemporaryDirectory() as temp:
            base = tree(Path(temp, "base"), {**files, ".github/actions/setup/action.yml": COMPOSITE})
            head = tree(Path(temp, "head"), {**files, ".github/workflows/new.yml": new,
                                             ".github/actions/setup/action.yml": PWN_COMPOSITE})
            report = compare(directory(base), directory(head))
        self.assertEqual(report["analysis"], "complete", report["diagnostics"])
        self.assertIn(("WF010", ".github/actions/setup/action.yml"),
                      {(f["rule"], f["file"]) for f in report["findings"]})

    def test_the_budget_still_limits_distinct_files(self):
        steps = "".join(f"      - uses: ./actions/a{i}\n" for i in range(MAX_EXTRA_FILES + 1))
        workflow = "on: pull_request_target\njobs:\n  big:\n    runs-on: ubuntu-latest\n    steps:\n" + steps
        actions = {f"actions/a{i}/action.yml": COMPOSITE for i in range(MAX_EXTRA_FILES + 1)}
        with tempfile.TemporaryDirectory() as temp:
            report = audit(directory(tree(Path(temp), {".github/workflows/w.yml": workflow, **actions})))
        self.assertEqual(report["analysis"], "incomplete")
        # Exactly the file past the budget is unreadable; the first 100 were read.
        self.assertEqual([d["reason"] for d in report["diagnostics"]],
                         [f"Local action actions/a{MAX_EXTRA_FILES} has no readable action.yml."])


class UnknownScope(unittest.TestCase):
    PWN = ("  j:\n    permissions: {contents: read}\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")

    def scan(self, head):
        base = "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        with tempfile.TemporaryDirectory() as temp:
            b = tree(Path(temp, "base"), {".github/workflows/w.yml": base})
            h = tree(Path(temp, "head"), {".github/workflows/w.yml": head})
            return compare(directory(b), directory(h))

    def test_an_unknown_scope_in_one_job_does_not_hide_findings_in_another(self):
        other = "  k:\n    permissions: {repository-projects: read}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        report = self.scan("on: pull_request_target\njobs:\n" + self.PWN + other)
        self.assertEqual(report["analysis"], "error")
        self.assertEqual([(f["rule"], f["job"]) for f in report["findings"]], [("WF010", "j")])
        self.assertEqual([d["job"] for d in report["diagnostics"]], ["k"])

    def test_an_unknown_workflow_scope_still_reports_code_flow(self):
        report = self.scan("on: pull_request_target\npermissions: {brand-new-scope: write}\njobs:\n"
                           + self.PWN.replace("    permissions: {contents: read}\n", ""))
        self.assertEqual(report["analysis"], "error")
        [finding] = [f for f in report["findings"] if f["rule"] == "WF010"]
        self.assertIn("token permissions that could not be read", finding["after"]["privileges"])


class MergeBase(unittest.TestCase):
    def run_action(self, repo, event_base, head, explicit_base=""):
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp, "event.json")
            event.write_text(json.dumps({"pull_request": {"base": {"sha": event_base}, "head": {"sha": head}}}))
            report = Path(temp, "report.json")
            env = {**os.environ, "GITHUB_EVENT_PATH": str(event), "PRIVILEGE_REPOSITORY": str(repo),
                   "PRIVILEGE_REPORT": str(report), "PRIVILEGE_BASE": explicit_base, "PRIVILEGE_HEAD": "",
                   "PRIVILEGE_SUMMARY": str(Path(temp, "summary.md")), "PRIVILEGE_SARIF": ""}
            subprocess.run([sys.executable, "-I", str(ROOT / "scripts/action_entry.py")], env=env,
                           capture_output=True, timeout=60, check=False)
            return json.loads(report.read_text())

    def test_stale_branches_compare_from_where_they_branched(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                               stderr=subprocess.DEVNULL).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            workflow = "on: push\npermissions: {contents: write}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{run: x}]\n"
            tree(repo, {".github/workflows/ci.yml": workflow})
            git("add", ".")
            git("commit", "-qm", "fork point")
            fork = git("rev-parse", "HEAD")
            git("checkout", "-qb", "pr")
            (repo / "README.md").write_text("docs only\n")
            git("add", ".")
            git("commit", "-qm", "README-only pull request")
            head = git("rev-parse", "HEAD")
            git("checkout", "-q", "main")
            (repo / ".github/workflows/ci.yml").write_text(workflow.replace("contents: write", "contents: read"))
            git("commit", "-qam", "hardening merged to main later")
            tip = git("rev-parse", "HEAD")

            from_event = self.run_action(repo, tip, head)
            explicit = self.run_action(repo, tip, head, explicit_base=tip)
        self.assertEqual((from_event["base"], from_event["findings"]), (fork, []))
        # An explicit base is still honoured exactly.
        self.assertEqual((explicit["base"], [f["rule"] for f in explicit["findings"]]), (tip, ["WF001"]))
