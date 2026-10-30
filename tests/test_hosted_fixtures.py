"""Run durable hosted fixtures against real local Git objects and controller."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hosted_fixture", ROOT / "scripts/hosted_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class HostedFixtures(unittest.TestCase):
    def test_all_hosted_inputs_and_outputs(self):
        cases = json.loads((ROOT / "tests/hosted_cases.json").read_text())
        for case, expected in cases.items():
            for mode in ("advisory", "require-complete"):
                with self.subTest(case=case, mode=mode), tempfile.TemporaryDirectory() as temp:
                    refs = fixture.create(case, temp)
                    env = {**os.environ, "RUNNER_TEMP": temp, "PRIVILEGE_MODE": mode,
                           "PRIVILEGE_BASE": refs["base"], "PRIVILEGE_HEAD": refs["head"],
                           "PRIVILEGE_DEFAULTS": "", "PRIVILEGE_REPOSITORY": refs["repo"],
                           "GITHUB_OUTPUT": str(Path(temp) / "outputs"),
                           "GITHUB_STEP_SUMMARY": str(Path(temp) / "summary")}
                    if case == "redirected":
                        env.update(GIT_DIR="/nonexistent/git-redirection", GIT_CONFIG_COUNT="not-a-number")
                    cp = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "scripts/action_runner.py")],
                                        cwd=temp, env=env, capture_output=True, text=True, timeout=30)
                    exit_code = 0 if expected["analysis"] == "complete" else 2
                    self.assertEqual(cp.returncode, 0 if mode == "advisory" else exit_code, cp.stderr)
                    report = json.loads(next(Path(temp).glob("workflow-privilege-report.*/report.json")).read_text())
                    self.assertEqual((report["analysis"], report["action"]["reviewStatus"]),
                                     (expected["analysis"], expected["review"]))
                    self.assertEqual(sorted(f["rule"] for f in report["findings"]), sorted(expected["rules"]))
                    if "secrets" in expected:
                        self.assertEqual(sorted(f["after"] for f in report["findings"] if f["rule"] == "WF004"),
                                         sorted(expected["secrets"]))


if __name__ == "__main__":
    unittest.main()
