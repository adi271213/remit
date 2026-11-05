from contextlib import redirect_stdout
import importlib.util
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
spec = importlib.util.spec_from_file_location("action_runner", ROOT / "scripts/action_runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def outputs(path):
    lines = path.read_text().splitlines()
    result = {}
    while lines:
        key, delimiter = lines.pop(0).split("<<", 1)
        values = []
        while lines[0] != delimiter:
            values.append(lines.pop(0))
        lines.pop(0)
        result[key] = "\n".join(values)
    return result


def finding(rule, job, line=None, after=None):
    return {"rule": rule, "file": ".github/workflows/ci.yml", "job": job, "line": line, "before": None,
            "after": after, "message": f"{rule} in {job}"}


def commands(text):
    """Workflow commands printed outside the ::stop-commands:: block."""
    lines, token = [], None
    for line in text.splitlines():
        if token:
            token = None if line == f"::{token}::" else token
        elif line.startswith("::stop-commands::"):
            token = line.removeprefix("::stop-commands::")
        elif line.startswith("::"):
            lines.append(line)
    return lines


class ActionOutcomes(unittest.TestCase):
    def invoke(self, root, *, mode="advisory", state="complete", findings=False, failure=None):
        env = {**os.environ, "RUNNER_TEMP": str(root), "PRIVILEGE_MODE": mode,
               "GITHUB_OUTPUT": str(root / "outputs"), "GITHUB_STEP_SUMMARY": str(root / "summary")}

        def execute(action_root, folder):
            if failure:
                raise failure
            report = {"analysis": state, "review": "suggested" if findings else "none",
                      "base": "a" * 40, "head": "b" * 40,
                      "findings": [{"rule": "WF001"}] if findings else [], "diagnostics": []}
            (folder / "report.json").write_text(json.dumps(report))
            (folder / "summary.md").write_text("## Test summary\n")
            return 0 if state == "complete" else 2

        with patch.dict(os.environ, env, clear=True), patch.object(runner, "execute", side_effect=execute), redirect_stdout(io.StringIO()):
            code = runner.run()
        return code, outputs(root / "outputs")

    def test_modes_and_statuses_are_distinct(self):
        for mode in ("advisory", "require-complete"):
            for state in ("complete", "incomplete", "error"):
                for findings in (False, True):
                    with self.subTest(mode=mode, state=state, findings=findings), tempfile.TemporaryDirectory() as temp:
                        root = Path(temp)
                        code, out = self.invoke(root, mode=mode, state=state, findings=findings)
                        self.assertEqual(code, 0 if mode == "advisory" or state == "complete" else 2)
                        self.assertEqual(out["analysis-status"], state)
                        self.assertEqual(out["review-status"], "suggested" if findings else "none" if state == "complete" else "unknown")
                        self.assertEqual(out["finding-count"], "1" if findings else "0")
                        self.assertEqual(out["analysis-exit-code"], "0" if state == "complete" else "2")
                        self.assertTrue(Path(out["report-path"]).is_file())
                        self.assertTrue(Path(out["summary-path"]).is_file())
                        self.assertIn("not approval to merge", (root / "summary").read_text())

    def test_bootstrap_failure_is_error_not_clean(self):
        for failure in (subprocess.CalledProcessError(1, "pip"), subprocess.TimeoutExpired("pip", 120), OSError("PRIVATE detail")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                code, out = self.invoke(root, failure=failure)
                self.assertEqual((code, out["analysis-status"], out["review-status"], out["analysis-exit-code"]), (0, "error", "unknown", "2"))
                self.assertNotIn("PRIVATE", Path(out["report-path"]).read_text())
                self.assertIn("Analysis error", (root / "summary").read_text())

    def test_invalid_mode_fails_with_published_error(self):
        with tempfile.TemporaryDirectory() as temp:
            code, out = self.invoke(Path(temp), mode="typo")
            self.assertEqual((code, out["analysis-status"], out["review-status"]), (2, "error", "unknown"))

    def test_empty_or_inconsistent_process_result_is_error(self):
        for child_code in (0, 1, 2):
            with self.subTest(code=child_code), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with patch.dict(os.environ, {"RUNNER_TEMP": temp, "GITHUB_OUTPUT": str(root / "out"), "PRIVILEGE_MODE": "advisory"}, clear=True), patch.object(runner, "execute", return_value=child_code), redirect_stdout(io.StringIO()):
                    self.assertEqual(runner.run(), 0)
                out = outputs(root / "out")
                self.assertEqual((out["analysis-status"], out["review-status"]), ("error", "unknown"))

    def test_real_entry_publishes_git_reports_outside_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Local test")
            git("config", "user.email", "test@example.invalid")
            git("config", "commit.gpgsign", "false")
            workflow = repo / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("on: push\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: [{run: echo fixture}]\n")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            workflow.write_text(workflow.read_text().replace("permissions: {}", "permissions: {contents: write}"))
            git("commit", "-qam", "head")
            head = git("rev-parse", "HEAD")
            env = {**os.environ, "RUNNER_TEMP": temp, "PRIVILEGE_MODE": "advisory", "PRIVILEGE_BASE": base,
                   "PRIVILEGE_HEAD": head, "PRIVILEGE_DEFAULTS": "", "PRIVILEGE_REPOSITORY": str(repo),
                   "GITHUB_OUTPUT": str(root / "out"), "GITHUB_STEP_SUMMARY": str(root / "summary")}
            with patch.dict(os.environ, env, clear=True), patch.object(runner, "bootstrap", return_value=Path(sys.executable)), redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(), 0)
            out = outputs(root / "out")
            self.assertEqual((out["analysis-status"], out["review-status"], out["finding-count"]), ("complete", "suggested", "1"))
            self.assertEqual((out["base-sha"], out["head-sha"]), (base, head))
            self.assertFalse(Path(out["report-path"]).is_relative_to(repo))
            self.assertIn("Review suggested", (root / "summary").read_text())
            self.assertEqual(json.loads(Path(out["report-path"]).read_text())["head"], head)

    def test_legacy_cli_and_entry_exit_contract_is_unchanged(self):
        env = {**os.environ, "PRIVILEGE_BASE": "invalid", "PRIVILEGE_HEAD": "invalid"}
        cp = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/action_entry.py")], env=env, capture_output=True)
        self.assertEqual(cp.returncode, 2)

    def test_reporting_failure_does_not_return_advisory_success(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(OSError):
                # A directory cannot be a GITHUB_OUTPUT file. The executable's
                # outer handler turns this failure into exit 2.
                with patch.dict(os.environ, {"RUNNER_TEMP": temp, "PRIVILEGE_MODE": "advisory", "GITHUB_OUTPUT": temp}, clear=True), patch.object(runner, "execute", return_value=1), redirect_stdout(io.StringIO()):
                    runner.run()


class Annotations(unittest.TestCase):
    def test_findings_become_line_annotations_with_escaped_text(self):
        finding = {"rule": "WF005", "file": ".github/workflows/ci.yml", "line": 7,
                   "message": "Runner prod,%\n::error::forged changed."}
        with patch.dict(os.environ, {"PRIVILEGE_REPOSITORY": ".", "GITHUB_WORKSPACE": os.getcwd()}, clear=True):
            [line] = runner.annotations([finding])
        self.assertEqual(line, "::warning file=.github/workflows/ci.yml,line=7,title=WF005 review suggested"
                               "::Runner prod,%25%0A::error::forged changed.")
        self.assertNotIn("\n", line)

    def test_annotations_are_capped_and_paths_follow_repository_path(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "sub").mkdir()
            findings = [{"rule": "WF001", "file": ".github/workflows/ci.yml", "line": None, "message": "m"}] * 12
            with patch.dict(os.environ, {"PRIVILEGE_REPOSITORY": str(Path(temp) / "sub"), "GITHUB_WORKSPACE": temp},
                            clear=True):
                lines = runner.annotations(findings)
        self.assertEqual(len(lines), 11)
        self.assertTrue(lines[0].startswith("::warning file=sub/.github/workflows/ci.yml,title="))
        self.assertIn("2 more findings", lines[-1])

    def test_the_most_serious_findings_are_annotated_first(self):
        # A write-all change in one job used to fill every annotation slot, so a pull request
        # checkout in another job never reached the diff.
        scopes = ("actions", "attestations", "checks", "contents", "deployments", "discussions",
                  "issues", "packages", "pages", "pull-requests", "security-events", "statuses")
        grants = [finding("WF001", "build", 6, {scope: "write"}) for scope in scopes]
        with patch.dict(os.environ, {"PRIVILEGE_REPOSITORY": ".", "GITHUB_WORKSPACE": os.getcwd()}, clear=True):
            lines = runner.annotations([*grants, finding("WF010", "label", 15)])
        self.assertEqual(len(lines), 2)
        self.assertIn("line=15,title=WF010 review suggested", lines[0])
        self.assertIn("line=6,title=WF001 review suggested::Job build gains 12 higher token permission scopes",
                      lines[1])
        self.assertIn("pull-requests: write", lines[1])

    def test_token_rows_are_combined_per_job_only(self):
        findings = [finding("WF001", "a", 3, {"contents": "write"}), finding("WF001", "b", 9, {"issues": "write"}),
                    finding("WF001", "a", 4, {"id-token": "write"})]
        with patch.dict(os.environ, {"PRIVILEGE_REPOSITORY": ".", "GITHUB_WORKSPACE": os.getcwd()}, clear=True):
            lines = runner.annotations(findings)
        self.assertEqual([line.split(",title=")[0].rsplit("line=", 1)[1] for line in lines], ["3", "9"])
        self.assertIn("contents: write, id-token: write", lines[0])

    def test_incomplete_analysis_warning_comes_first_within_the_limit(self):
        findings = [finding("WF004", f"job{n}", n + 1) for n in range(12)]
        with patch.dict(os.environ, {"PRIVILEGE_REPOSITORY": ".", "GITHUB_WORKSPACE": os.getcwd()}, clear=True):
            lines = runner.annotations(findings, "incomplete")
        warnings = [line for line in lines if line.startswith("::warning")]
        self.assertTrue(warnings[0].startswith("::warning title=Remit analysis incomplete::"))
        self.assertEqual(len(warnings), runner.MAX_ANNOTATIONS)
        self.assertIn("3 more findings", lines[-1])

    def test_the_controller_prints_the_analysis_warning_once_and_first(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def execute(action_root, folder):
                report = {"analysis": "incomplete", "review": "suggested", "base": "a" * 40, "head": "b" * 40,
                          "findings": [finding("WF004", f"job{n}", n + 1) for n in range(12)],
                          "diagnostics": [{"file": "x", "side": "head", "job": None, "kind": "incomplete",
                                           "reason": "r"}]}
                (folder / "report.json").write_text(json.dumps(report))
                (folder / "summary.md").write_text("## Test summary\n")
                return 2

            env = {"RUNNER_TEMP": temp, "PRIVILEGE_MODE": "advisory", "GITHUB_OUTPUT": str(root / "out"),
                   "PRIVILEGE_REPOSITORY": ".", "GITHUB_WORKSPACE": os.getcwd()}
            stdout = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(runner, "execute", side_effect=execute), \
                    redirect_stdout(stdout):
                self.assertEqual(runner.run(), 0)
        warnings = [line for line in commands(stdout.getvalue()) if line.startswith("::warning")]
        self.assertEqual(sum("Remit analysis incomplete" in line for line in warnings), 1)
        self.assertIn("Remit analysis incomplete", warnings[0])
        self.assertLessEqual(len(warnings), runner.MAX_ANNOTATIONS)
