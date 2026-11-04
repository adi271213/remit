"""SARIF output for GitHub code scanning."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from privilege_check.cli import main
from privilege_check.sarif import RULES, sarif
from privilege_check.scan import compare, error_report
from privilege_check.sources import Snapshot

WF = ".github/workflows/ci.yml"
BASE = "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
HEAD = BASE.replace("permissions: {}", "permissions: {contents: write}")


def scan(head, base=BASE):
    return compare(Snapshot("base", {WF: base}), Snapshot("head", {WF: head}))


class Sarif(unittest.TestCase):
    def test_findings_become_results_on_their_lines(self):
        log = sarif(scan(HEAD))
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "workflow-privilege-check")
        [result] = run["results"]
        self.assertEqual(result["ruleId"], "WF001")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual((location["artifactLocation"]["uri"], location["region"]["startLine"]), (WF, 2))
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_every_reported_rule_has_metadata(self):
        rule_ids = {rule["id"] for rule in sarif(scan(HEAD))["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, set(RULES))
        self.assertTrue(all(rule.startswith("WF") for rule in rule_ids))

    def test_fingerprint_survives_unrelated_line_moves(self):
        moved = HEAD.replace("on: push", "# comment\non: push")
        first, second = (sarif(scan(head))["runs"][0]["results"][0] for head in (HEAD, moved))
        self.assertNotEqual(first["locations"], second["locations"])
        self.assertEqual(first["partialFingerprints"], second["partialFingerprints"])

    def test_diagnostics_become_execution_notifications(self):
        log = sarif(error_report("Could not read comparison inputs."))
        invocation = log["runs"][0]["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["toolExecutionNotifications"][0]["level"], "error")
        self.assertEqual(log["runs"][0]["results"], [])

    def test_cli_prints_sarif_and_can_write_it_alongside_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for side, text in (("base", BASE), ("head", HEAD)):
                (root / side / ".github/workflows").mkdir(parents=True)
                (root / side / WF).write_text(text)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["scan", "--dirs", str(root / "base"), str(root / "head"), "--format", "sarif"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["runs"][0]["results"][0]["ruleId"], "WF001")
            with contextlib.redirect_stdout(io.StringIO()):
                main(["scan", "--dirs", str(root / "base"), str(root / "head"), "--sarif", str(root / "r.sarif")])
            self.assertEqual(len(json.loads((root / "r.sarif").read_text())["runs"][0]["results"]), 1)
