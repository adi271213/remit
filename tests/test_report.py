"""Human-readable deltas must retain evidence, uncertainty and literal input text."""
import copy
from pathlib import Path
import sys
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from privilege_check.report import markdown
from privilege_check.scan import compare, parse
from privilege_check.sources import Snapshot

WF = ".github/workflows/ci.yml"
BASE = "on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: echo fixture}]\n"


def scan(head, *, base=BASE, extra_head=None):
    return compare(Snapshot("base", {WF: base}), Snapshot("head", {WF: head, **(extra_head or {})}))


class DeltaReport(unittest.TestCase):
    def test_report_explains_both_token_levels_and_preserves_structured_facts(self):
        report = scan(BASE.replace("contents: read", "contents: write"))
        original = copy.deepcopy(report)
        text = markdown(report)
        self.assertIn("Job: build", text)
        self.assertIn("| Rule | Before | After | Change |", text)
        self.assertIn("| WF001 | contents: read | contents: write |", text)
        self.assertIn("Confirm that this job needs the new token scopes", text)
        self.assertEqual(report, original)

    def test_token_guidance_is_not_repeated_for_every_scope_in_a_job(self):
        report = scan(BASE.replace("contents: read", "contents: write, packages: write"))
        self.assertEqual(len(report["findings"]), 2)
        text = markdown(report)
        self.assertEqual(text.count("Job: build"), 1)
        self.assertEqual(text.count("Confirm that this job needs the new token scopes"), 1)
        self.assertIn("packages: none | packages: write", text)

    def test_partial_analysis_keeps_known_delta_and_unresolved_reason(self):
        for extra in ("on: workflow_dispatch\njobs:\n  unknown:\n    runs-on: ubuntu-latest\n    steps: [{run: echo fixture}]\n",
                      "on: workflow_dispatch\njobs: [unclosed\n"):
            with self.subTest(extra=extra):
                report = scan(BASE.replace("contents: read", "contents: write"),
                              extra_head={".github/workflows/unresolved.yml": extra})
                self.assertIn(report["analysis"], ("incomplete", "error"))
                text = markdown(report)
                self.assertTrue(text.startswith("## Analysis " + report["analysis"]))
                self.assertIn("contents: read | contents: write", text)
                self.assertIn("### Unresolved analysis", text)
                self.assertIn(report["diagnostics"][0]["reason"], text)
                self.assertNotIn("No supported privilege expansions detected", text)

    def test_new_reference_does_not_claim_a_secret_was_absent(self):
        doc = parse(BASE)
        doc["jobs"]["build"]["steps"][0]["run"] = "echo ${{ secrets.NEW_TOKEN }}"
        report = scan(yaml.safe_dump(doc))
        text = markdown(report)
        self.assertIn("| WF004 | Not recorded | NEW&#95;TOKEN |", text)
        self.assertIn("does not establish whether a runtime resource exists", text)
        self.assertIn("Review its consumer", text)
        self.assertNotIn("secret did not exist", text)

    def test_new_value_cannot_inject_markdown_html_or_table_rows(self):
        doc = parse(BASE)
        doc["jobs"]["build"]["runs-on"] = "prod|![pixel](https://example.invalid/pixel)<script>\n## forged"
        report = scan(yaml.safe_dump(doc))
        self.assertEqual(report["analysis"], "complete")
        text = markdown(report)
        self.assertIn("&#124;", text)
        self.assertIn("&#33;&#91;pixel&#93;&#40;", text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("](", text)
        self.assertNotIn("\n## forged", text)

    def test_long_context_values_are_disclosed_as_shortened_without_mutating_evidence(self):
        label = "internal-" + "x" * 500
        report = scan(BASE.replace("ubuntu-latest", label))
        original = copy.deepcopy(report)
        text = markdown(report)
        self.assertIn("shortened; see JSON", text)
        self.assertIn("JSON report retains the full recorded values", text)
        self.assertNotIn(label, text)
        self.assertEqual(report, original)
        self.assertEqual(report["findings"][0]["after"]["labels"], [label])

    def test_neutral_report_does_not_add_a_review_request(self):
        report = scan(BASE.replace("echo fixture", "echo updated"))
        text = markdown(report)
        self.assertIn("No supported privilege expansions detected", text)
        self.assertNotIn("Review:", text)
        self.assertNotIn("| Before |", text)
