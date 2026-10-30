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
            git("add", "."); git("commit", "-qm", "base"); base = git("rev-parse", "HEAD")
            workflow.write_text(workflow.read_text().replace("permissions: {}", "permissions: {contents: write}"))
            git("commit", "-qam", "head"); head = git("rev-parse", "HEAD")
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
            root = Path(temp)
            with self.assertRaises(OSError):
                # A directory cannot be a GITHUB_OUTPUT file. The executable's
                # outer handler turns this failure into exit 2.
                with patch.dict(os.environ, {"RUNNER_TEMP": temp, "PRIVILEGE_MODE": "advisory", "GITHUB_OUTPUT": temp}, clear=True), patch.object(runner, "execute", return_value=1), redirect_stdout(io.StringIO()):
                    runner.run()
