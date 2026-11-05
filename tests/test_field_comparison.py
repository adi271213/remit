"""The field comparison script reads its own output format."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Summarize(unittest.TestCase):
    def test_summary_counts_remit_and_related_new_findings(self):
        rows = [
            {"repository": "a/b", "commit": "1", "parent": "0",
             "remit": {"analysis": "complete", "seconds": 0.1, "diagnostics": [],
                       "findings": [{"rule": "WF003", "file": "w.yml", "job": None},
                                    {"rule": "WF004", "file": "w.yml", "job": "j"}]},
             "zizmor": [["dangerous-triggers", "w.yml", None, 1], ["template-injection", "w.yml", "j", 2]],
             "poutine": []},
            {"repository": "a/b", "commit": "2", "parent": "1",
             "remit": {"analysis": "incomplete", "seconds": 0.3, "diagnostics": ["x"], "findings": []},
             "zizmor": [], "poutine": []},
        ]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "results.jsonl")
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            out = subprocess.run([sys.executable, str(ROOT / "scripts/field_comparison.py"), "summarize", str(path)],
                                 capture_output=True, text=True, check=True).stdout
        summary = json.loads(out)
        self.assertEqual(summary["remitAnalysis"], {"complete": 1, "incomplete": 1})
        self.assertEqual(summary["newFindings"], {"remit": 2, "zizmor": 3, "poutine": 0})
        self.assertEqual(summary["remitByRule"], {"WF003": {"findings": 1, "alsoNewInAnotherTool": 1},
                                                  "WF004": {"findings": 1, "alsoNewInAnotherTool": 0}})

    def test_commit_list_is_well_formed(self):
        lines = (ROOT / "benchmarks/field/commits.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"), ["repository", "commit", "parent"])
        for line in lines[1:]:
            slug, commit, parent = line.split("\t")
            self.assertRegex(slug, r"^[\w.-]+/[\w.-]+$")
            self.assertRegex(commit + parent, r"^[0-9a-f]{80}$")


if __name__ == "__main__":
    unittest.main()
