"""WF010/WF011 through environment variables, step and job outputs, and action inputs."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit.scan import audit, compare
from remit.sources import directory

WF = ".github/workflows/w.yml"
TARGET = "on: pull_request_target\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
GATED = "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
SHA = "${{ github.event.pull_request.head.sha }}"
REF = "${{ github.event.pull_request.head.ref }}"


def tree(root, files):
    (root / ".github/workflows").mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    return root


def audited(files):
    with tempfile.TemporaryDirectory() as temp:
        report = audit(directory(tree(Path(temp), files)))
    return [(f["rule"], f["line"], f["after"]["ref"]) for f in report["findings"]]


def checkout(ref):
    return f"      - uses: actions/checkout@v4\n        with:\n          ref: {ref}\n"


class FollowsIndirection(unittest.TestCase):
    def assertFinds(self, files, rule, line, source):
        [(found_rule, found_line, ref)] = audited(files)
        self.assertEqual((found_rule, found_line), (rule, line))
        self.assertIn(source, ref)

    def test_job_and_workflow_environment(self):
        self.assertFinds({WF: TARGET + f"    env:\n      SHA: {SHA}\n    steps:\n" + checkout("${{ env.SHA }}")},
                         "WF010", 8, "head.sha")
        workflow_env = (f"on: pull_request_target\nenv:\n  REF: {REF}\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                        "    steps:\n      - run: |\n          git fetch origin \"$REF\"\n          git checkout FETCH_HEAD\n")
        self.assertFinds({WF: workflow_env}, "WF010", 8, "head.ref")

    def test_step_environment_and_braced_shell_variable(self):
        step = TARGET + f"    steps:\n      - run: git checkout ${{REF}}\n        env:\n          REF: {SHA}\n"
        self.assertFinds({WF: step}, "WF010", 6, "head.sha")

    def test_github_output_and_github_env_writes(self):
        output = (TARGET + f"    steps:\n      - id: pr\n        run: echo \"sha={SHA}\" >> \"$GITHUB_OUTPUT\"\n"
                  + checkout("${{ steps.pr.outputs.sha }}"))
        self.assertFinds({WF: output}, "WF010", 8, "head.sha")
        env = (TARGET + f"    steps:\n      - run: echo \"PRREF={REF}\" >> $GITHUB_ENV\n"
               + checkout("${{ env.PRREF }}"))
        self.assertFinds({WF: env}, "WF010", 7, "head.ref")

    def test_github_script_set_output(self):
        script = (TARGET + "    steps:\n      - id: s\n        uses: actions/github-script@v7\n        with:\n"
                  "          script: core.setOutput('ref', context.payload.pull_request.head.ref)\n"
                  + checkout("${{ steps.s.outputs.ref }}"))
        self.assertFinds({WF: script}, "WF010", 10, "context.payload.pull_request.head.ref")

    def test_needs_outputs_follow_the_dependency(self):
        jobs = ("on: pull_request_target\njobs:\n  info:\n    runs-on: ubuntu-latest\n    outputs:\n"
                "      sha: ${{ steps.p.outputs.sha }}\n    steps:\n      - id: p\n"
                f"        run: echo \"sha={SHA}\" >> $GITHUB_OUTPUT\n"
                "  build:\n    needs: info\n    runs-on: ubuntu-latest\n    steps:\n" + checkout("${{ needs.info.outputs.sha }}"))
        self.assertFinds({WF: jobs}, "WF010", 14, "head.sha")
        self.assertEqual(audited({WF: jobs.replace("    needs: info\n", "")}), [])

    def test_composite_inputs_and_outputs_and_reusable_inputs(self):
        action = ".github/actions/co/action.yml"
        into = {WF: TARGET + f"    steps:\n      - uses: ./.github/actions/co\n        with:\n          revision: {SHA}\n",
                action: "runs:\n  using: composite\n  steps:\n" + checkout("${{ inputs.revision }}").replace("      ", "    ")}
        self.assertFinds(into, "WF010", 4, "head.sha")
        back = {WF: TARGET + "    steps:\n      - id: info\n        uses: ./.github/actions/co\n"
                + checkout("${{ steps.info.outputs.sha }}"),
                action: ("outputs:\n  sha:\n    value: ${{ steps.x.outputs.sha }}\nruns:\n  using: composite\n  steps:\n"
                         f"    - id: x\n      shell: bash\n      run: echo \"sha={SHA}\" >> $GITHUB_OUTPUT\n")}
        self.assertFinds(back, "WF010", 8, "head.sha")
        called = ".github/workflows/r.yml"
        reusable = {WF: f"on: pull_request_target\njobs:\n  call:\n    uses: ./{called}\n    with:\n      ref: {REF}\n",
                    called: ("on:\n  workflow_call:\n    inputs:\n      ref: {type: string}\njobs:\n  b:\n"
                             "    runs-on: ubuntu-latest\n    steps:\n" + checkout("${{ inputs.ref }}"))}
        self.assertFinds(reusable, "WF010", 9, "head.ref")

    def test_toctou_survives_indirection(self):
        self.assertFinds({WF: GATED + f"    env:\n      R: {REF}\n    steps:\n" + checkout("${{ env.R }}")},
                         "WF011", 10, "head.ref")
        lookup = (GATED + "    steps:\n      - id: pr\n        run: echo \"sha=$(gh pr view ${{ github.event.number }} "
                  "--json headRefOid -q .headRefOid)\" >> $GITHUB_OUTPUT\n" + checkout("${{ steps.pr.outputs.sha }}"))
        # Looked up after approval, so even a SHA can differ from what was approved.
        self.assertFinds({WF: lookup}, "WF011", 10, "looked up while the job runs")


class LookAlikesStayQuiet(unittest.TestCase):
    def test_safe_values_and_scoping(self):
        cases = {
            "safe env": TARGET + "    env:\n      SHA: ${{ github.sha }}\n    steps:\n" + checkout("${{ env.SHA }}"),
            "safe output": (TARGET + "    steps:\n      - id: v\n        run: echo \"v=$(cat VERSION)\" >> $GITHUB_OUTPUT\n"
                            + checkout("${{ steps.v.outputs.v }}")),
            "other job's env": ("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                                f"    env:\n      REF: {REF}\n    steps:\n      - run: echo $REF\n"
                                "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git checkout $REF\n"),
            "step env scope": (TARGET + f"    steps:\n      - run: echo hi\n        env:\n          REF: {REF}\n"
                               "      - run: git checkout $REF\n"),
            "not a git command": TARGET + f"    env:\n      R: {REF}\n    steps:\n      - run: echo \"$R\"\n",
            "pull_request": (TARGET.replace("pull_request_target", "pull_request")
                             + f"    env:\n      SHA: {SHA}\n    steps:\n" + checkout("${{ env.SHA }}")),
        }
        for name, workflow in cases.items():
            with self.subTest(name):
                self.assertEqual(audited({WF: workflow}), [])


class DiffMode(unittest.TestCase):
    def scan(self, base, head):
        with tempfile.TemporaryDirectory() as temp:
            return [(f["rule"]) for f in compare(directory(tree(Path(temp, "b"), {WF: base})),
                                                 directory(tree(Path(temp, "h"), {WF: head})))["findings"]
                    if f["rule"] in ("WF010", "WF011")]

    def test_new_indirect_checkout_is_reported_and_unchanged_one_is_quiet(self):
        safe = TARGET + "    env:\n      SHA: ${{ github.sha }}\n    steps:\n" + checkout("${{ env.SHA }}")
        risky = safe.replace("${{ github.sha }}", SHA)
        self.assertEqual(self.scan(safe, risky), ["WF010"])
        self.assertEqual(self.scan(risky, risky.replace("ubuntu-latest", "ubuntu-24.04")), [])
