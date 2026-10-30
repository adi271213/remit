import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import yaml
from privilege_check.scan import StrictLoader, compare, parse
from privilege_check.sources import Snapshot
from privilege_check.yaml_limits import validate_graph

WF = ".github/workflows/ci.yml"
CASES = json.loads((ROOT / "tests/alias_cases.json").read_text())


def scan(base, head):
    return compare(Snapshot("base", {WF: base}), Snapshot("head", {WF: head}))


class AliasTests(unittest.TestCase):
    def test_security_and_context_cases(self):
        for case in CASES:
            with self.subTest(case=case["case"]):
                report = scan(case["base"], case["head"])
                self.assertEqual(report["analysis"], case["analysis"])
                self.assertEqual(report["review"], "suggested" if case["rules"] else "none")
                self.assertEqual(sorted(f["rule"] for f in report["findings"]), case["rules"])

    def test_aliases_match_fully_inlined_reports(self):
        class InlineDumper(yaml.SafeDumper):
            def ignore_aliases(self, data):
                return True

        for case in CASES:
            if case["analysis"] == "error":
                continue
            with self.subTest(case=case["case"]):
                base, head = (yaml.dump(parse(case[side]), Dumper=InlineDumper)
                              for side in ("base", "head"))
                self.assertEqual(scan(case["base"], case["head"]), scan(base, head))

    def test_rejected_graphs_never_reach_construction(self):
        for name in ("alias-cycle", "alias-hidden-bomb", "alias-matrix-bomb", "alias-scalar-bomb"):
            case = next(c for c in CASES if c["case"] == name)
            with self.subTest(case=name), patch.object(StrictLoader, "construct_document") as construct:
                with self.assertRaises(ValueError):
                    parse(case["head"])
                construct.assert_not_called()

    def test_depth_counts_alias_paths_not_just_source_nesting(self):
        chain = "a0: &a0 [x]\n" + "".join(f"a{i}: &a{i} [*a{i-1}]\n" for i in range(1, 51))
        with self.assertRaisesRegex(ValueError, "depth"):
            parse(chain + CASES[0]["base"])

    def test_exact_graph_budget_boundaries(self):
        node = yaml.compose("[&x ab, *x]")
        with patch("privilege_check.yaml_limits.MAX_EXPANDED_NODES", 3), \
             patch("privilege_check.yaml_limits.MAX_EXPANDED_SCALAR_BYTES", 4), \
             patch("privilege_check.yaml_limits.MAX_EXPANDED_DEPTH", 2):
            validate_graph(node)
        for limit, value in (("NODES", 2), ("SCALAR_BYTES", 3), ("DEPTH", 1)):
            with self.subTest(limit=limit), patch("privilege_check.yaml_limits.MAX_EXPANDED_" + limit, value):
                with self.assertRaises(ValueError):
                    validate_graph(node)

    def test_alias_count_at_limit_is_accepted(self):
        prefix = "scalar: &scalar x\nuses: [" + ",".join(["*scalar"] * 499) + "]\n"
        parse(prefix + CASES[0]["base"])

    def test_shared_objects_are_not_mutated_by_comparison(self):
        case = next(c for c in CASES if c["case"] == "alias-matrix")
        doc = parse(case["head"])
        original = copy.deepcopy(doc)
        with patch("privilege_check.scan.parse", return_value=doc):
            scan(case["base"], case["head"])
        self.assertEqual(doc, original)

    def test_aliases_do_not_weaken_duplicate_keys_or_tags(self):
        for text in ("permissions: &p {}\npermissions: *p\n", "extra: !!python/object/apply:os.system [echo]\n"):
            with self.subTest(text=text):
                self.assertEqual(scan(CASES[0]["base"], text + CASES[0]["head"])["analysis"], "error")

    def test_multifile_errors_preserve_independent_known_findings(self):
        neutral = CASES[0]["base"]
        valid = next(c for c in CASES if c["case"] == "alias-token")
        bad = next(c for c in CASES if c["case"] == "alias-cycle")
        base = Snapshot("base", {WF: neutral, ".github/workflows/bad.yml": neutral})
        head = Snapshot("head", {WF: valid["head"], ".github/workflows/bad.yml": bad["head"]})
        report = compare(base, head)
        self.assertEqual(report["analysis"], "error")
        self.assertEqual(report["review"], "suggested")
        self.assertEqual([f["rule"] for f in report["findings"]], ["WF001", "WF001"])

    def test_hostile_inputs_finish_in_fresh_process(self):
        program = """
import json, sys
sys.path.insert(0, sys.argv[1])
from privilege_check.scan import parse
for text in json.load(sys.stdin):
    try: parse(text)
    except ValueError: pass
    else: raise AssertionError('Hostile YAML was accepted')
"""
        texts = [c["head"] for c in CASES if c["case"] in
                 ("alias-cycle", "alias-hidden-bomb", "alias-matrix-bomb", "alias-scalar-bomb")]
        result = subprocess.run([sys.executable, "-I", "-c", program, str(ROOT / "src")],
                                input=json.dumps(texts), capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
