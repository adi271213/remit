"""Fixes from running Remit on 446 recent workflow commits in 30 public repositories.

Each test reproduces, in miniature, a pattern found in that comparison.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit.conditions import excludes_pull_request_runs, workflow_run_excludes_pull_requests  # noqa: E402
from remit.scan import audit, compare  # noqa: E402
from remit.sources import MAX_FILE, directory, git_snapshot  # noqa: E402

WF = ".github/workflows/ci.yml"
ACTION = ".github/actions/setup/action.yml"


def write(root, files):
    (root / ".github/workflows").mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)


def scan(base, head, repository=None):
    with tempfile.TemporaryDirectory() as temp:
        write(Path(temp, "base"), base)
        write(Path(temp, "head"), head)
        return compare(directory(Path(temp, "base")), directory(Path(temp, "head")), repository=repository)


def check(files, repository=None):
    with tempfile.TemporaryDirectory() as temp:
        write(Path(temp), files)
        return audit(directory(Path(temp)), repository=repository)


def rules(report):
    return sorted(f["rule"] for f in report["findings"])


JOB = "  {name}:\n    runs-on: ubuntu-latest\n{extra}    steps:\n      - run: make\n"


def workflow(*jobs, on="push", permissions=None):
    top = f"on: {on}\n" + (f"permissions: {permissions}\n" if permissions else "") + "jobs:\n"
    return top + "".join(jobs)


class ReadOnlyScopesOnNewJobs(unittest.TestCase):
    def test_new_job_declaring_read_scopes_is_quiet(self):
        base = workflow(JOB.format(name="a", extra=""), permissions="{contents: read}")
        head = base + JOB.format(name="b", extra="    permissions: {contents: read, actions: read}\n")
        self.assertEqual(rules(scan({WF: base}, {WF: head})), [])

    def test_new_job_write_scope_and_oidc_are_still_reported(self):
        base = workflow(JOB.format(name="a", extra=""), permissions="{contents: read}")
        head = base + JOB.format(name="b", extra="    permissions: {contents: write, id-token: write}\n")
        self.assertEqual(rules(scan({WF: base}, {WF: head})), ["WF001", "WF001"])

    def test_read_scope_added_to_an_existing_job_is_still_reported(self):
        base = workflow(JOB.format(name="a", extra="    permissions: {contents: read}\n"))
        head = workflow(JOB.format(name="a", extra="    permissions: {contents: read, actions: read}\n"))
        self.assertEqual(rules(scan({WF: base}, {WF: head})), ["WF001"])


class RunnersBecomingHosted(unittest.TestCase):
    BASE = workflow("  a:\n    runs-on: ${{ inputs.runner }}\n    steps:\n      - run: make\n", permissions="{}")

    def test_unresolved_runner_replaced_by_a_hosted_one_is_quiet_and_complete(self):
        report = scan({WF: self.BASE}, {WF: self.BASE.replace("${{ inputs.runner }}", "macos-15")})
        self.assertEqual((report["analysis"], rules(report)), ("complete", []))

    def test_unresolved_runner_replaced_by_self_hosted_is_still_reported(self):
        report = scan({WF: self.BASE}, {WF: self.BASE.replace("${{ inputs.runner }}", "[self-hosted, linux]")})
        self.assertEqual(rules(report), ["WF005"])


class LargeWorkflows(unittest.TestCase):
    BIG = workflow(JOB.format(name="a", extra=""), permissions="{}") + "#" * (300 * 1024) + "\n"

    def test_workflows_up_to_one_mebibyte_are_analysed(self):
        head = self.BIG.replace("permissions: {}", "permissions: {contents: write}")
        report = scan({WF: self.BIG}, {WF: head})
        self.assertEqual((report["analysis"], rules(report)), ("complete", ["WF001"]))

    def test_an_unchanged_oversized_workflow_does_not_block_the_rest(self):
        huge = "#" * (MAX_FILE + 1)
        other = ".github/workflows/other.yml"
        base = {WF: huge, other: workflow(JOB.format(name="a", extra=""), permissions="{}")}
        head = {WF: huge, other: base[other].replace("permissions: {}", "permissions: {contents: write}")}
        report = scan(base, head)
        self.assertEqual((report["analysis"], rules(report)), ("complete", ["WF001"]))

    def test_a_changed_oversized_workflow_is_incomplete_not_an_error(self):
        report = scan({WF: "#" * (MAX_FILE + 1)}, {WF: "#" * (MAX_FILE + 2)})
        self.assertEqual(report["analysis"], "incomplete")
        self.assertIn("larger than", report["diagnostics"][0]["reason"])

    def test_git_snapshots_fingerprint_oversized_workflows(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                               stderr=subprocess.DEVNULL).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            write(repo, {WF: "#" * (MAX_FILE + 1)})
            git("add", ".")
            git("commit", "-qm", "base")
            (repo / WF).write_text("#" * (MAX_FILE + 2))
            git("commit", "-qam", "head")
            unchanged = compare(git_snapshot(repo, "HEAD"), git_snapshot(repo, "HEAD"))
            changed = compare(git_snapshot(repo, "HEAD~1"), git_snapshot(repo, "HEAD"))
        self.assertEqual(unchanged["analysis"], "complete")
        self.assertEqual(changed["analysis"], "incomplete")


class DeepNesting(unittest.TestCase):
    def chain(self, levels, tail):
        files = {}
        for i in range(levels):
            files[f".github/actions/a{i}/action.yml"] = (
                f"runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/a{i + 1}\n")
        files[f".github/actions/a{levels}/action.yml"] = f"runs:\n  using: composite\n  steps:\n{tail}"
        return files

    def test_six_levels_of_composite_actions_are_followed(self):
        caller = workflow("  a:\n    runs-on: ubuntu-latest\n    permissions: {contents: write}\n    steps:\n"
                          "      - uses: ./.github/actions/a0\n", on="push")
        quiet = "    - run: make\n      shell: bash\n"
        base = {WF: caller, **self.chain(6, quiet)}
        head = {WF: caller, **self.chain(6, "    - uses: someone/tool@v1\n")}
        report = scan(base, head)
        self.assertEqual((report["analysis"], rules(report)), ("complete", ["WF009"]))

    def test_nesting_beyond_ten_levels_is_incomplete(self):
        caller = workflow("  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/a0\n")
        quiet = "    - run: make\n      shell: bash\n"
        report = check({WF: caller.replace("on: push", "on: pull_request_target"), **self.chain(11, quiet)})
        self.assertEqual(report["analysis"], "incomplete")


class CheckoutsIntoTheWorkspace(unittest.TestCase):
    CALLER = ("on: push\npermissions: {{contents: write}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
              "{checkouts}      - uses: ./{path}\n")
    COMPOSITE = "runs:\n  using: composite\n  steps:\n    - run: make\n      shell: bash\n"

    def test_this_repository_checked_out_into_a_folder_is_followed(self):
        checkout = "      - uses: actions/checkout@v4\n        with:\n          path: tools\n"
        caller = self.CALLER.format(checkouts=checkout, path="tools/.github/actions/setup")
        base = {WF: caller, ACTION: self.COMPOSITE}
        head = {WF: caller, ACTION: self.COMPOSITE + "    - uses: someone/tool@v1\n"}
        report = scan(base, head)
        self.assertEqual((report["analysis"], rules(report)), ("complete", ["WF009"]))
        self.assertEqual(report["findings"][0]["file"], ACTION)

    def test_a_checkout_of_this_repository_at_an_expression_ref_is_still_followed(self):
        checkout = ("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.workflow_sha }}\n"
                    "          path: .harness\n")
        caller = self.CALLER.format(checkouts=checkout, path=".harness/.github/actions/setup")
        report = scan({WF: caller, ACTION: self.COMPOSITE}, {WF: caller, ACTION: self.COMPOSITE + "    - uses: x/y@v1\n"})
        self.assertEqual((report["analysis"], rules(report)), ("complete", ["WF009"]))

    def test_an_action_from_another_checked_out_repository_is_third_party_code(self):
        checkout = ("      - uses: actions/checkout@v4\n        with:\n          repository: other/tools\n"
                    "          ref: v2\n          path: tools\n")
        base = {WF: self.CALLER.format(checkouts="", path=".github/actions/setup"), ACTION: self.COMPOSITE}
        head = {WF: self.CALLER.format(checkouts=checkout, path="tools/.github/actions/notify"), ACTION: self.COMPOSITE}
        report = scan(base, head)
        self.assertEqual((report["analysis"], rules(report)), ("complete", ["WF009"]))
        self.assertEqual(report["findings"][0]["after"]["uses"], "other/tools/.github/actions/notify@v2")

    def test_another_repository_at_the_workspace_root_replaces_this_one(self):
        checkout = "      - uses: actions/checkout@v4\n        with:\n          repository: other/tools\n"
        base = {WF: self.CALLER.format(checkouts="", path=".github/actions/setup"), ACTION: self.COMPOSITE}
        head = {WF: self.CALLER.format(checkouts=checkout, path=".github/actions/setup"), ACTION: self.COMPOSITE}
        report = scan(base, head)
        self.assertEqual(rules(report), ["WF009"])
        self.assertEqual(report["findings"][0]["after"]["uses"], "other/tools/.github/actions/setup (default branch)")


class WorkflowRunConditions(unittest.TestCase):
    TEMPLATE = ("on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\npermissions: {{contents: write}}\n"
                "jobs:\n{jobs}")
    STEP = ("    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
            "          ref: ${{ github.event.workflow_run.head_sha }}\n      - run: make\n")

    def wf010(self, jobs):
        return [f["job"] for f in check({WF: self.TEMPLATE.format(jobs=jobs)})["findings"] if f["rule"] == "WF010"]

    def test_runs_limited_to_push_and_dispatch_are_quiet(self):
        condition = "github.event.workflow_run.event == 'push' || github.event.workflow_run.event == 'workflow_dispatch'"
        self.assertEqual(self.wf010(f"  a:\n    if: {condition}\n" + self.STEP), [])

    def test_runs_from_pull_requests_are_reported(self):
        self.assertEqual(self.wf010("  a:\n    if: github.event.workflow_run.event == 'pull_request'\n" + self.STEP),
                         ["a"])
        self.assertEqual(self.wf010("  a:\n" + self.STEP), ["a"])

    def test_a_condition_on_a_needed_job_counts(self):
        gate = "  check:\n    if: github.event.workflow_run.event == 'push'\n    runs-on: ubuntu-latest\n" \
               "    steps:\n      - run: echo ok\n"
        self.assertEqual(self.wf010(gate + "  a:\n    needs: check\n" + self.STEP), [])
        # always() runs the job even when the gate job was skipped.
        self.assertEqual(self.wf010(gate + "  a:\n    needs: check\n    if: always()\n" + self.STEP), ["a"])

    def test_condition_evaluation_never_trusts_what_it_cannot_decide(self):
        decided = {
            "github.event.workflow_run.event == 'push'": True,
            "${{ github.event.workflow_run.event == 'PUSH' }}": True,
            "!(github.event.workflow_run.event != 'schedule')": True,
            "github.event_name == 'workflow_dispatch' || github.event.workflow_run.event == 'push'": True,
            "github.event.workflow_run.event == 'push' || contains(github.event.workflow_run.head_branch, 'x')": False,
            "github.event.workflow_run.event != 'pull_request'": False,
            "github.event.workflow_run.conclusion == 'success'": False,
            "success()": False,
            "github.event.workflow_run.event == 'push' ((": False,
        }
        for condition, expected in decided.items():
            with self.subTest(condition=condition):
                self.assertIs(excludes_pull_request_runs(condition), expected)
        self.assertFalse(workflow_run_excludes_pull_requests({"jobs": {"a": {"needs": ["a"]}}}, "a"))


class OwnRepositoryReferences(unittest.TestCase):
    CALLED = "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"

    def caller(self, ref):
        return ("on: push\npermissions: {contents: write}\njobs:\n  a:\n"
                f"    uses: acme/app/.github/workflows/called.yml@{ref}\n    secrets: inherit\n")

    def wf009(self, ref, repository):
        base = {WF: "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n",
                ".github/workflows/called.yml": self.CALLED}
        head = {**base, WF: self.caller(ref)}
        return [f for f in scan(base, head, repository=repository)["findings"] if f["rule"] == "WF009"]

    def test_own_repository_by_branch_is_not_third_party(self):
        self.assertEqual(self.wf009("main", "Acme/App"), [])

    def test_without_the_repository_name_it_is_still_reported(self):
        self.assertEqual(len(self.wf009("main", None)), 1)

    def test_a_full_sha_may_be_a_fork_commit_and_is_still_reported(self):
        self.assertEqual(len(self.wf009("a" * 40, "acme/app")), 1)

    def test_repository_name_is_validated(self):
        with self.assertRaises(ValueError):
            scan({}, {}, repository="not a name")


class SharedCodeFindings(unittest.TestCase):
    def test_one_change_in_a_shared_action_is_one_finding(self):
        jobs = "".join(f"  {name}:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/setup\n"
                       for name in ("build", "lint", "test"))
        caller = "on: push\npermissions: {contents: write}\njobs:\n" + jobs
        composite = "runs:\n  using: composite\n  steps:\n    - run: make\n      shell: bash\n"
        report = scan({WF: caller, ACTION: composite},
                      {WF: caller, ACTION: composite + "    - uses: someone/tool@v1\n"})
        [finding] = report["findings"]
        self.assertEqual([j["job"] for j in finding["jobs"]], ["build", "lint", "test"])
        self.assertTrue(finding["message"].startswith("Each of jobs build, lint and test now runs third-party code"))


if __name__ == "__main__":
    unittest.main()


class DeclaringPermissions(unittest.TestCase):
    """From the 30 held-out repositories: most WF002 findings were hardening changes."""
    INHERITED = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"

    def declared(self, block):
        return self.INHERITED.replace("    runs-on:", f"    permissions: {block}\n    runs-on:")

    def test_a_read_only_block_replacing_the_default_is_quiet(self):
        report = scan({WF: self.INHERITED}, {WF: self.declared("{contents: read, issues: read, pull-requests: read}")})
        self.assertEqual(rules(report), [])

    def test_a_block_with_a_write_scope_is_still_reported(self):
        report = scan({WF: self.INHERITED}, {WF: self.declared("{issues: read, packages: write}")})
        self.assertEqual([(f["rule"], f["after"]) for f in report["findings"]], [("WF002", {"packages": "write"})])
