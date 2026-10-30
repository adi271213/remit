"""Execute the copy-ready fetch step against real local Git pull refs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class InstallationFetch(unittest.TestCase):
    def invoke(self, *, expected=None, number="1", publish_ref=True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            origin, checkout = root / "origin", root / "checkout"
            origin.mkdir()
            checkout.mkdir()

            def git(repo, *args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                               stderr=subprocess.DEVNULL).strip()

            git(origin, "init", "-q", "-b", "main")
            git(origin, "config", "user.name", "Install fixture")
            git(origin, "config", "user.email", "fixture@example.invalid")
            git(origin, "config", "commit.gpgsign", "false")
            (origin / "proposed.py").write_text("raise RuntimeError('proposed code')\n")
            git(origin, "add", ".")
            git(origin, "commit", "-qm", "fixture")
            sha = git(origin, "rev-parse", "HEAD")
            if publish_ref:
                git(origin, "update-ref", "refs/pull/1/head", sha)
            git(checkout, "init", "-q", "-b", "main")
            git(checkout, "remote", "add", "origin", str(origin))
            workflow = yaml.safe_load((ROOT / "examples/github-action-template.yml").read_text())
            step = next(s for s in workflow["jobs"]["privilege-review"]["steps"]
                        if s["name"] == "Fetch proposed head as data")
            env = {**os.environ, "PR_NUMBER": number, "EXPECTED_HEAD": expected or sha,
                   "GIT_TERMINAL_PROMPT": "0"}
            result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                                    cwd=checkout, env=env, capture_output=True, text=True, timeout=15)
            self.assertFalse((checkout / "proposed.py").exists())
            head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "--verify", "HEAD"],
                                  capture_output=True)
            self.assertNotEqual(head.returncode, 0, "Fetching must not check out the PR head")
            return result, sha, git(checkout, "status", "--porcelain")

    def test_matching_head_succeeds_without_checkout(self):
        result, _, status = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(status, "")

    def test_moving_head_fails_with_retry_diagnostic(self):
        result, _, _ = self.invoke(expected="f" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match this event", result.stdout)
        self.assertIn("keep this equality check", result.stdout)

    def test_invalid_event_input_fails_before_fetch(self):
        for kwargs in ({"number": "--upload-pack=bad"}, {"expected": "not-a-sha"}):
            with self.subTest(kwargs=kwargs):
                result, _, _ = self.invoke(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("is invalid", result.stdout)
                self.assertNotIn("From ", result.stderr)

    def test_missing_pull_ref_fails_with_fetch_diagnostic(self):
        result, _, _ = self.invoke(publish_ref=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Could not fetch the public PR head", result.stdout)
        self.assertNotIn("does not match this event", result.stdout)
