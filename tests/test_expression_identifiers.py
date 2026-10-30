"""Expression identifier boundaries must not invent or hide capabilities."""
from pathlib import Path
import sys
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from privilege_check.scan import compare
from privilege_check.sources import Snapshot

WF = ".github/workflows/check.yml"


def workflow(expressions):
    return yaml.safe_dump({
        "on": {"workflow_dispatch": {"inputs": {"use-secrets": {"type": "boolean", "default": False}}}},
        "permissions": {}, "jobs": {"check": {"runs-on": "ubuntu-latest", "steps": [
            {"env": {f"VALUE_{i}": expression for i, expression in enumerate(expressions)}, "run": "echo fixture"}
        ]}}}, sort_keys=False)


def scan(before, after):
    return compare(Snapshot("base", {WF: before}), Snapshot("head", {WF: after}))


class ExpressionIdentifiers(unittest.TestCase):
    def test_hyphenated_property_names_do_not_invent_secret_access(self):
        for expression in ("inputs.use-secrets", "matrix.use-secrets", "steps.use-secrets.outputs.ready",
                           "needs.release-job.outputs.use-secrets", "inputs.use-secrets-more",
                           "inputs['use-secrets']", "format('{0}', inputs.use-secrets)"):
            with self.subTest(expression=expression):
                report = scan(workflow([]), workflow(["${{ " + expression + " }}"]))
                self.assertEqual((report["analysis"], report["review"], report["findings"]), ("complete", "none", []))

    def test_nonsecret_baseline_does_not_hide_new_secret(self):
        for baseline in ("${{ inputs.use-secrets }}", "${{ needs.release-job.outputs.use-secrets }}"):
            for reference in ("${{ secrets.DEPLOY_KEY }}", "${{ secrets['DEPLOY_KEY'] }}"):
                with self.subTest(baseline=baseline, reference=reference):
                    report = scan(workflow([baseline]), workflow([baseline, reference]))
                    self.assertEqual((report["analysis"], report["review"]), ("complete", "suggested"))
                    self.assertEqual([(f["rule"], f["after"]) for f in report["findings"]], [("WF004", "DEPLOY_KEY")])

    def test_secret_property_prefix_does_not_hide_a_different_reference(self):
        # A missing secret property still has a literal name; it is not the
        # shorter, different property before the hyphen. Availability is unknown.
        for reference in ("${{ secrets.DEPLOY-KEY }}", "${{ secrets['DEPLOY-KEY'] }}"):
            report = scan(workflow([reference]), workflow([reference, "${{ secrets.DEPLOY }}"]))
            self.assertEqual((report["analysis"], report["review"]), ("complete", "suggested"))
            self.assertEqual([f["after"] for f in report["findings"]], ["DEPLOY"])

    def test_real_secret_context_and_quoted_text_keep_their_meaning(self):
        for reference in ("${{ toJSON(secrets) }}", "${{ SECRETS }}"):
            report = scan(workflow(["${{ inputs.use-secrets }}"]), workflow([reference]))
            self.assertEqual([f["after"] for f in report["findings"]], ["all available secrets"])
        for expression in ("${{ 'secrets.DEPLOY_KEY' }}", "${{ inputs.secrets }}", "${{ inputs.use-secrets }}"):
            report = scan(workflow([]), workflow([expression]))
            self.assertEqual(report["findings"], [])
        report = scan(workflow(["${{ toJSON(secrets) }}"]), workflow(["${{ secrets.DEPLOY_KEY }}"]))
        self.assertEqual(report["findings"], [])

    def test_dynamic_reference_keeps_known_new_secret(self):
        report = scan(workflow(["${{ inputs.use-secrets }}"]), workflow([
            "${{ inputs.use-secrets }}", "${{ secrets.DEPLOY_KEY }}", "${{ secrets[inputs.which] }}"]))
        self.assertEqual((report["analysis"], report["review"]), ("incomplete", "suggested"))
        self.assertEqual([f["after"] for f in report["findings"]], ["DEPLOY_KEY"])

    def test_hyphenated_matrix_fields_detect_pairing_changes(self):
        def matrix_workflow(swapped=False):
            rows = [{"runner-name": "ubuntu-latest", "environment-name": "production"},
                    {"runner-name": "self-hosted", "environment-name": "staging"}]
            if swapped:
                rows[0]["environment-name"], rows[1]["environment-name"] = "staging", "production"
            return yaml.safe_dump({"on": "workflow_dispatch", "permissions": {}, "jobs": {"deploy": {
                "strategy": {"matrix": {"include": rows}}, "runs-on": "${{ matrix.runner-name }}",
                "environment": "${{ matrix.environment-name }}", "steps": [{"run": "echo fixture"}]}}}, sort_keys=False)
        report = scan(matrix_workflow(), matrix_workflow(True))
        self.assertEqual((report["analysis"], [f["rule"] for f in report["findings"]]), ("complete", ["WF008"]))
        report = scan(matrix_workflow(), matrix_workflow().replace("echo fixture", "echo changed"))
        self.assertEqual((report["analysis"], report["findings"]), ("complete", []))


if __name__ == "__main__":
    unittest.main()
