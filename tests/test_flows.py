"""WF009-WF011 through local code, pull request content in privileged workflows, and TOCTOU."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit.report import markdown
from remit.scan import compare
from remit.sources import directory, git_snapshot

WF = ".github/workflows/ci.yml"
ACTION = ".github/actions/setup/action.yml"
TARGET = """on: pull_request_target
permissions: {contents: read}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
HEAD_SHA = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
COMPOSITE = "runs:\n  using: composite\n  steps:\n    - run: echo setup\n      shell: bash\n"
CALLER = """on: pull_request_target
permissions: {contents: write}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup
"""

# A composite action the strict loader refuses (duplicate key). Exceeding the alias, token or
# depth limits fails the same way.
UNPARSEABLE = "name: setup\nname: again\n" + COMPOSITE


def write(root, files):
    (root / ".github/workflows").mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)


def scan(base, head):
    with tempfile.TemporaryDirectory() as temp:
        write(Path(temp, "base"), base)
        write(Path(temp, "head"), head)
        return compare(directory(Path(temp, "base")), directory(Path(temp, "head")))


def rules(report, *names):
    return [(f["rule"], f["file"], f["line"]) for f in report["findings"] if f["rule"] in names]


class PullRequestContent(unittest.TestCase):
    def test_checkout_of_head_in_pull_request_target_is_wf010(self):
        report = scan({WF: TARGET}, {WF: TARGET.replace("      - uses: actions/checkout@v4\n", HEAD_SHA)})
        self.assertEqual(rules(report, "WF010", "WF011"), [("WF010", WF, 7)])
        self.assertEqual(report["findings"][-1]["after"]["triggers"], ["pull_request_target"])

    def test_same_checkout_in_pull_request_is_quiet(self):
        base = TARGET.replace("pull_request_target", "pull_request")
        report = scan({WF: base}, {WF: base.replace("      - uses: actions/checkout@v4\n", HEAD_SHA)})
        self.assertEqual(rules(report, "WF010", "WF011"), [])

    def test_switching_trigger_makes_an_existing_checkout_privileged(self):
        checkout = TARGET.replace("      - uses: actions/checkout@v4\n", HEAD_SHA)
        report = scan({WF: checkout.replace("pull_request_target", "pull_request")}, {WF: checkout})
        self.assertEqual([r[0] for r in rules(report, "WF010", "WF011")], ["WF010"])

    def test_unchanged_privileged_checkout_stays_quiet(self):
        checkout = TARGET.replace("      - uses: actions/checkout@v4\n", HEAD_SHA)
        report = scan({WF: checkout}, {WF: checkout.replace("ubuntu-latest", "ubuntu-24.04")})
        self.assertEqual(rules(report, "WF010", "WF011"), [])

    def test_workflow_run_artifact_download_is_wf010_and_version_bumps_are_quiet(self):
        base = ("on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\npermissions: {pull-requests: write}\n"
                "jobs:\n  comment:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        download = ("      - uses: actions/download-artifact@v4\n        with:\n"
                    "          run-id: ${{ github.event.workflow_run.id }}\n")
        head = base + download
        self.assertEqual([r[0] for r in rules(scan({WF: base}, {WF: head}), "WF010")], ["WF010"])
        self.assertEqual(rules(scan({WF: head}, {WF: head.replace("@v4", "@v5")}), "WF010"), [])

    def test_script_fetch_must_name_the_pull_request_on_the_same_line(self):
        script = ("      - run: |\n          git checkout -b backport\n"
                  "          git cherry-pick ${{ github.event.pull_request.merge_commit_sha }}\n")
        self.assertEqual(rules(scan({WF: TARGET}, {WF: TARGET + script}), "WF010"), [])
        fetch = "      - run: git fetch origin ${{ github.event.pull_request.head.sha }}\n"
        self.assertEqual([r[0] for r in rules(scan({WF: TARGET}, {WF: TARGET + fetch}), "WF010")], ["WF010"])


class TimeOfCheckTimeOfUse(unittest.TestCase):
    GATED = ("on:\n  pull_request_target:\n    types: [labeled]\npermissions: {contents: read}\njobs:\n  test:\n"
             "    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')\n    runs-on: ubuntu-latest\n"
             "    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: REF\n")

    def test_label_gate_with_mutable_ref_is_wf011(self):
        report = scan({WF: self.GATED.replace("REF", "main")},
                      {WF: self.GATED.replace("REF", "${{ github.event.pull_request.head.ref }}")})
        self.assertEqual(rules(report, "WF010", "WF011"), [("WF011", WF, 10)])
        self.assertEqual(report["findings"][-1]["after"]["gate"], "a label")

    def test_label_gate_with_head_sha_is_not_toctou(self):
        report = scan({WF: self.GATED.replace("REF", "main")},
                      {WF: self.GATED.replace("REF", "${{ github.event.pull_request.head.sha }}")})
        self.assertEqual([r[0] for r in rules(report, "WF010", "WF011")], ["WF010"])

    def test_comment_command_with_pr_checkout_is_wf011(self):
        base = ("on: issue_comment\njobs:\n  test:\n    if: contains(github.event.comment.body, '/ok-to-test')\n"
                "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        head = base.replace("      - run: echo hi\n", "      - run: gh pr checkout ${{ github.event.issue.number }}\n")
        report = scan({WF: base}, {WF: head})
        self.assertEqual([r[0] for r in rules(report, "WF010", "WF011")], ["WF011"])

    def test_adding_the_gate_turns_an_existing_mutable_checkout_into_toctou(self):
        ungated = self.GATED.replace("    types: [labeled]\n", "").replace(
            "    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')\n", "")
        ungated = ungated.replace("on:\n  pull_request_target:\n", "on: pull_request_target\n")
        mutable = "${{ github.event.pull_request.head.ref }}"
        report = scan({WF: ungated.replace("REF", mutable)}, {WF: self.GATED.replace("REF", mutable)})
        self.assertEqual([r[0] for r in rules(report, "WF010", "WF011")], ["WF011"])


class LocalCode(unittest.TestCase):
    def test_change_inside_a_composite_action_reaches_the_unchanged_workflow(self):
        report = scan({WF: CALLER, ACTION: COMPOSITE}, {WF: CALLER, ACTION: COMPOSITE + "    - uses: someone/tool@v1\n"})
        self.assertEqual(report["examinedFiles"], [WF])
        [item] = [f for f in report["findings"] if f["rule"] == "WF009"]
        self.assertEqual((item["file"], item["line"], item["job"], item["workflow"]), (ACTION, 6, "build", WF))
        self.assertIn("(in .github/workflows/ci.yml)", markdown(report).replace("&#95;", "_"))

    def test_unchanged_composite_and_workflow_are_not_examined(self):
        report = scan({WF: CALLER, ACTION: COMPOSITE}, {WF: CALLER, ACTION: COMPOSITE})
        self.assertEqual((report["examinedFiles"], report["findings"]), ([], []))

    def test_pull_request_checkout_inside_a_composite_is_wf010(self):
        checkout = "    - uses: actions/checkout@v4\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n"
        report = scan({WF: CALLER, ACTION: COMPOSITE}, {WF: CALLER, ACTION: COMPOSITE + checkout})
        self.assertEqual(rules(report, "WF010"), [("WF010", ACTION, 6)])

    def test_reusable_workflow_code_runs_with_the_callers_privileges(self):
        caller = "on: push\npermissions: {}\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    secrets: inherit\n"
        called = "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
        build = ".github/workflows/build.yml"
        report = scan({WF: caller, build: called}, {WF: caller, build: called + "      - uses: someone/deploy@v2\n"})
        [item] = [f for f in report["findings"] if f["rule"] == "WF009" and f["job"] == "call"]
        self.assertEqual((item["file"], item["after"]["privileges"]), (build, ["all secrets"]))

    def test_missing_escaping_and_cyclic_references_are_bounded(self):
        missing = scan({WF: TARGET}, {WF: TARGET + "      - uses: ./.github/actions/missing\n"})
        self.assertEqual(missing["analysis"], "incomplete")
        escape = scan({WF: TARGET}, {WF: TARGET + "      - uses: ./../outside\n"})
        self.assertIn("outside the repository", escape["diagnostics"][0]["reason"])
        a = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/b\n"
        b = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/a\n    - uses: someone/x@v1\n"
        files = {WF: CALLER.replace("setup", "a"), ".github/actions/a/action.yml": a, ".github/actions/b/action.yml": b}
        report = scan(files, {**files, ".github/actions/b/action.yml": b.replace("someone/x", "someone/y")})
        self.assertEqual([f["after"]["uses"] for f in report["findings"] if f["rule"] == "WF009"], ["someone/y@v1"])

    def test_an_unparseable_local_action_is_reported_when_only_the_action_changed(self):
        # The failure used to be recorded only on the first load, which happened inside the
        # dependency check, so a pull request that changed only the action was reported complete.
        report = scan({WF: CALLER, ACTION: COMPOSITE}, {WF: CALLER, ACTION: UNPARSEABLE})
        self.assertEqual(report["analysis"], "incomplete")
        self.assertEqual([(d["file"], d["side"], d["job"], d.get("area")) for d in report["diagnostics"]],
                         [(WF, "head", "build", "local-code")])

    def test_unparseable_local_action_outcome_does_not_depend_on_workflow_order(self):
        for unchanged, edited in ((".github/workflows/a.yml", ".github/workflows/z.yml"),
                                  (".github/workflows/z.yml", ".github/workflows/a.yml")):
            with self.subTest(edited=edited):
                report = scan({unchanged: CALLER, edited: CALLER, ACTION: COMPOSITE},
                              {unchanged: CALLER, edited: CALLER + "# edited\n", ACTION: UNPARSEABLE})
                self.assertEqual(report["analysis"], "incomplete")
                self.assertEqual(sorted(d["file"] for d in report["diagnostics"]), sorted([unchanged, edited]))

    def test_a_change_between_two_unparseable_versions_is_still_examined(self):
        report = scan({WF: CALLER, ACTION: UNPARSEABLE}, {WF: CALLER, ACTION: UNPARSEABLE + "    - run: make\n"})
        self.assertEqual((report["examinedFiles"], report["analysis"]), ([WF], "incomplete"))

    def test_an_unchanged_unparseable_action_with_an_unchanged_workflow_stays_quiet(self):
        report = scan({WF: CALLER, ACTION: UNPARSEABLE}, {WF: CALLER, ACTION: UNPARSEABLE})
        self.assertEqual((report["examinedFiles"], report["analysis"], report["diagnostics"]), ([], "complete", []))

    def test_symlinked_local_action_is_not_read(self):
        with tempfile.TemporaryDirectory() as temp:
            for side in ("base", "head"):
                write(Path(temp, side), {WF: CALLER})
            outside = Path(temp, "outside.yml")
            outside.write_text(COMPOSITE + "    - uses: someone/tool@v1\n")
            Path(temp, "head/.github/actions/setup").mkdir(parents=True)
            os.symlink(outside, Path(temp, "head", ACTION))
            report = compare(directory(Path(temp, "base")), directory(Path(temp, "head")))
        self.assertEqual([f for f in report["findings"] if f["rule"] == "WF009"], [])

    def test_git_snapshots_read_local_actions_from_commits(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                               stderr=subprocess.DEVNULL).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            write(repo, {WF: CALLER, ACTION: COMPOSITE})
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (repo / ACTION).write_text(COMPOSITE + "    - uses: someone/tool@v1\n")
            git("commit", "-qam", "head")
            report = compare(git_snapshot(repo, base), git_snapshot(repo, "HEAD"))
        self.assertEqual(rules(report, "WF009"), [("WF009", ACTION, 6)])
