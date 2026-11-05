"""Linear-time scanning of repository-controlled text, and helpers without other coverage."""
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit import flows  # noqa: E402
from remit.scan import compare  # noqa: E402
from remit.sources import Snapshot, merge_base  # noqa: E402

# The patterns the linear scanners replaced; they define the expected results.
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
FILE_WRITE = re.compile(r"""([A-Za-z_][\w-]*)=(.*?)["']?\s*>>\s*["']?\$\{?(GITHUB_OUTPUT|GITHUB_ENV)\}?""")
PR_API = re.compile(r"\bgh\s+pr\s+view\b|\bgh\s+api\b[^\n]*\bpulls\b|api\.github\.com/repos/[^\s'\"]*/pulls",
                    re.IGNORECASE)
ATOMS = ["${{", "}}", "{", "}", "$", "a", "Z", "_", "-", "9", "é", "=", " ", "\t", " ", '"', "'", ">>", ">",
         "\n", "GITHUB_OUTPUT", "GITHUB_ENV", "$GITHUB_ENV", "${GITHUB_OUTPUT}", "x=1", "echo ", "gh", "api", "gh api ",
         "gh pr view", "pulls", "PULLS", "/pulls", "api.github.com/repos/", "o/r", "/", ";", "\r"]


class LinearScanners(unittest.TestCase):
    def test_same_results_as_the_patterns_they_replace(self):
        rng = random.Random(2026)
        for _ in range(20000):
            text = "".join(rng.choice(ATOMS) for _ in range(rng.randint(0, 25)))
            with self.subTest(text=text):
                self.assertEqual(flows.expressions(text), EXPRESSION.findall(text))
                self.assertEqual(flows.without_expressions(text), EXPRESSION.sub("", text))
                self.assertEqual(flows.pull_request_lookup(text), bool(PR_API.search(text)))
                for line in text.splitlines():
                    self.assertEqual(flows.file_writes(line), FILE_WRITE.findall(line))

    def test_hostile_long_lines_stay_fast(self):
        # Each of these took minutes with the backtracking patterns.
        n = 400_000
        shapes = ["x" * n, "a=" * (n // 2), "${{ " * (n // 4), "git checkout " + "gh api " * (n // 7),
                  "git fetch " + "gh\napi " * (n // 8), ("x=" + " " * 50 + ">> ") * (n // 55)]
        for text in shapes:
            job = {"runs-on": "ubuntu-latest",
                   "steps": [{"id": "s", "run": text}, {"run": "git checkout $A", "env": {"A": text}}]}
            head = {".github/workflows/w.yml": repr({"on": "pull_request_target", "jobs": {"a": job}})}
            start = time.process_time()
            compare(Snapshot("b", {}), Snapshot("h", head))
            self.assertLess(time.process_time() - start, 15, text[:20])


class MergeBase(unittest.TestCase):
    def test_the_fork_point_of_two_branches(self):
        with tempfile.TemporaryDirectory() as temp:
            def git(*args):
                return subprocess.check_output(["git", "-C", temp, *args], text=True, stderr=subprocess.DEVNULL).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            git("commit", "-q", "--allow-empty", "-m", "fork point")
            fork = git("rev-parse", "HEAD")
            git("checkout", "-q", "-b", "feature")
            git("commit", "-q", "--allow-empty", "-m", "feature work")
            head = git("rev-parse", "HEAD")
            git("checkout", "-q", "main")
            git("commit", "-q", "--allow-empty", "-m", "base moved on")
            base = git("rev-parse", "HEAD")
            self.assertEqual(merge_base(temp, base, head), fork)
            self.assertIsNone(merge_base(temp, base, "0" * 40))


if __name__ == "__main__":
    unittest.main()
