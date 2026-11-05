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

    def test_comparisons_across_types_are_unknown(self):
        # GitHub converts mismatched operands to numbers, so each right-hand side
        # below is true and the job runs for every pull request.
        push = "github.event.workflow_run.event == 'push'"
        for evasion in ("1 == '1'", "null == ''", "'0x1' == 1", "true == 1", "false == '0'",
                        "github.event.workflow_run.event == 0", "!(1 != '1')"):
            with self.subTest(evasion=evasion):
                self.assertFalse(excludes_pull_request_runs(f"{push} || {evasion}"))
        # Same-type comparisons are still decided.
        for condition in (f"{push} || 1 == 2", f"{push} || 'a' == 'b'", f"{push} || true == false",
                          f"{push} || null != null", f"{push} && 1 == 1"):
            with self.subTest(condition=condition):
                self.assertTrue(excludes_pull_request_runs(condition))


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


class DocumentOnlyCheckouts(unittest.TestCase):
    """deepseek-harness pattern: a pull_request_target job checks out only the README of the
    pull request head. That is quiet only when no later step can execute or interpret it."""
    SPARSE = ("      - uses: actions/checkout@v4\n        with:\n"
              "          ref: ${{ github.event.pull_request.head.sha }}\n"
              "          sparse-checkout: {files}\n{cone}")
    CONE_OFF = "          sparse-checkout-cone-mode: false\n"
    UPLOAD = "      - uses: actions/upload-artifact@v4\n        with:\n          path: README.md\n"

    def wf010(self, files="README.md", cone=CONE_OFF, after=UPLOAD, action=None):
        workflow = ("on: pull_request_target\npermissions: {contents: read}\njobs:\n  check:\n"
                    "    runs-on: ubuntu-latest\n    steps:\n" + self.SPARSE.format(files=files, cone=cone) + after)
        files_ = {WF: workflow, **({ACTION: action} if action else {})}
        return [f for f in check(files_)["findings"] if f["rule"] in ("WF010", "WF011")]

    def test_documentation_only_checkout_followed_by_inert_steps_is_quiet(self):
        self.assertEqual(self.wf010(), [])
        self.assertEqual(self.wf010(after=""), [])
        self.assertEqual(self.wf010(files="|\n            README.md\n            docs/guide.md\n"), [])

    def test_an_external_action_may_execute_documentation_so_it_is_reported(self):
        # The action's behaviour is unknown: it may render, template or run what it reads,
        # and here it is also handed the pull request's head commit.
        for after in ("      - uses: owner/check@v1\n",
                      "      - uses: owner/check@v1\n        with:\n"
                      "          sha: ${{ github.event.pull_request.head.sha }}\n",
                      "      - uses: actions/github-script@v7\n        with:\n"
                      "          script: require('./README.md')\n",
                      self.UPLOAD + "      - uses: docker://alpine:3\n"):
            with self.subTest(after=after):
                self.assertEqual(len(self.wf010(after=after)), 1)

    def test_cone_mode_includes_every_root_file_so_it_is_reported(self):
        self.assertEqual(len(self.wf010(cone="")), 1)

    def test_a_later_script_can_restore_the_whole_tree_so_it_is_reported(self):
        self.assertEqual(len(self.wf010(after="      - run: git sparse-checkout disable && make\n")), 1)

    def test_a_later_local_action_is_reported(self):
        composite = "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
        self.assertEqual(len(self.wf010(after="      - uses: ./.github/actions/setup\n", action=composite)), 1)

    def test_build_files_and_globs_are_not_documentation(self):
        for files in ("package.json", "requirements.txt", "'*.md'", "README.md\n            Makefile"):
            with self.subTest(files=files):
                pattern = files if "\n" not in files else "|\n            " + files
                self.assertEqual(len(self.wf010(files=pattern)), 1)

    def test_inside_a_composite_action_the_callers_later_steps_are_unknown(self):
        composite = ("runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n      with:\n"
                     "        ref: ${{ github.event.pull_request.head.sha }}\n        sparse-checkout: README.md\n"
                     "        sparse-checkout-cone-mode: false\n")
        workflow = ("on: pull_request_target\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: ./.github/actions/setup\n      - run: make\n")
        found = [f["rule"] for f in check({WF: workflow, ACTION: composite})["findings"]]
        self.assertIn("WF010", found)


class EnvironmentOverrides(unittest.TestCase):
    """A pull request value stops counting once the variable is replaced with a known value;
    a replacement that can't be resolved keeps it."""
    HEAD = "${{ github.event.pull_request.head.sha }}"

    def wf010(self, job_env="", steps=""):
        workflow = ("on: pull_request_target\npermissions: {contents: read}\n"
                    f"env:\n  REF: {self.HEAD}\njobs:\n  build:\n    runs-on: ubuntu-latest\n{job_env}"
                    "    steps:\n" + steps)
        return [f for f in check({WF: workflow})["findings"] if f["rule"] in ("WF010", "WF011")]

    CHECKOUT = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ env.REF }}\n"

    def test_the_workflow_value_is_reported(self):
        self.assertEqual(len(self.wf010(steps=self.CHECKOUT)), 1)

    def test_a_known_value_at_job_or_step_level_clears_it(self):
        for job_env, step_env in (("    env:\n      REF: main\n", ""),
                                  ("    env:\n      REF: ${{ github.sha }}\n", ""),
                                  ("", "        env:\n          REF: main\n")):
            with self.subTest(job_env=job_env, step_env=step_env):
                self.assertEqual(self.wf010(job_env, self.CHECKOUT + step_env), [])

    def test_a_step_level_override_applies_to_that_step_only(self):
        steps = ("      - run: echo hi\n        env:\n          REF: main\n" + self.CHECKOUT)
        self.assertEqual(len(self.wf010(steps=steps)), 1)

    def test_github_env_writes_clear_or_set_for_later_steps(self):
        cleared = '      - run: echo "REF=main" >> "$GITHUB_ENV"\n' + self.CHECKOUT
        self.assertEqual(self.wf010(steps=cleared), [])
        workflow_free = ("on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                         f'      - run: echo "REF={self.HEAD}" >> "$GITHUB_ENV"\n' + self.CHECKOUT)
        self.assertEqual(len([f for f in check({WF: workflow_free})["findings"] if f["rule"] == "WF010"]), 1)

    def test_an_unresolved_replacement_keeps_the_value(self):
        for job_env, steps in (("    env:\n      REF: ${{ inputs.ref }}\n", self.CHECKOUT),
                               ("    env:\n      REF: ${{ vars.BRANCH }}-${{ env.REF }}\n", self.CHECKOUT),
                               ("", '      - run: echo "REF=$(cat ref.txt)" >> "$GITHUB_ENV"\n' + self.CHECKOUT),
                               ("", '      - run: echo "REF=$OTHER" >> "$GITHUB_ENV"\n' + self.CHECKOUT)):
            with self.subTest(job_env=job_env, steps=steps):
                self.assertEqual(len(self.wf010(job_env, steps)), 1)


class PullRequestContentWording(unittest.TestCase):
    """WF010 states what was seen: execution and cache writes only when a step runs the content."""

    def message(self, steps, permissions="{contents: write}"):
        workflow = (f"on: pull_request_target\npermissions: {permissions}\njobs:\n  a:\n"
                    "    runs-on: ubuntu-latest\n    steps:\n" + steps)
        found = [f for f in check({WF: workflow})["findings"] if f["rule"] == "WF010"]
        self.assertEqual(len(found), 1)
        return found[0]

    CHECKOUT = ("      - uses: actions/checkout@v4\n        with:\n"
                "          ref: ${{ github.event.pull_request.head.sha }}\n")

    def test_a_later_script_supports_the_execution_claim(self):
        found = self.message(self.CHECKOUT + "      - run: npm test\n")
        self.assertIn("A script (line 10) runs after it, which can execute", found["message"])
        self.assertIn("Actions cache", found["message"])
        self.assertEqual(found["after"]["runBy"], "a script (line 10)")

    def test_without_a_runner_it_claims_only_the_import(self):
        found = self.message(self.CHECKOUT + "      - uses: owner/lint@v1\n", "{contents: read}")
        self.assertIn("brings in pull request content", found["message"])
        self.assertIn("The job has a read-only token.", found["message"])
        for claim in ("can execute", "Actions cache", "act with"):
            self.assertNotIn(claim, found["message"])
        self.assertNotIn("runBy", found["after"])

    def test_a_fetching_script_counts_only_when_it_runs_something_else(self):
        number = "${{ github.event.pull_request.number }}"
        self.assertIn("The same script", self.message(f"      - run: gh pr checkout {number} && make\n")["message"])
        quiet = self.message(f"      - run: gh pr checkout {number} && git log -1\n")["message"]
        self.assertNotIn("can execute", quiet)


class CacheInPrivilegedJobs(unittest.TestCase):
    """WF012: a job with publishing power starts restoring the Actions cache."""
    JOB = ("on: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n"
           "{extra}    steps:\n      - uses: actions/checkout@v4\n{setup}      - run: npm publish\n"
           "        env:\n          NODE_AUTH_TOKEN: ${{{{ secrets.NPM_TOKEN }}}}\n")

    def found(self, base_setup, head_setup, extra="      id-token: write\n", files=None):
        base = {WF: self.JOB.format(extra=extra, setup=base_setup), **(files or {})}
        head = {WF: self.JOB.format(extra=extra, setup=head_setup), **(files or {})}
        return [f for f in scan(base, head)["findings"] if f["rule"] == "WF012"]

    NODE = "      - uses: actions/setup-node@{version}\n        with:\n          node-version: 24\n{more}"

    def test_a_new_cache_restore_is_reported(self):
        for setup in (self.NODE.format(version="v4", more="          cache: pnpm\n"),
                      "      - uses: actions/cache/restore@v4\n        with:\n          path: x\n          key: k\n",
                      "      - uses: actions/setup-go@v5\n",
                      "      - uses: ruby/setup-ruby@v1\n        with:\n          bundler-cache: true\n"):
            with self.subTest(setup=setup):
                found = self.found("", setup)
                self.assertEqual(len(found), 1)
                self.assertIn("NPM_TOKEN", found[0]["message"])

    def test_version_defaults_are_applied(self):
        # setup-node v5 turns on npm caching by default; v4 did not.
        found = self.found(self.NODE.format(version="v4", more=""), self.NODE.format(version="v5", more=""))
        self.assertEqual(len(found), 1)
        self.assertIn("v5 automatic npm cache", found[0]["message"])
        off = "          package-manager-cache: false\n"
        self.assertEqual(self.found(self.NODE.format(version="v4", more=""),
                                    self.NODE.format(version="v5", more=off)), [])
        # setup-go v3 does not cache unless asked.
        self.assertEqual(self.found("", "      - uses: actions/setup-go@v3\n"), [])

    def test_unchanged_or_unprivileged_caches_are_quiet(self):
        cached = self.NODE.format(version="v4", more="          cache: npm\n")
        self.assertEqual(self.found(cached, self.NODE.format(version="v4", more="          cache: pnpm\n")), [])
        unprivileged = ("on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    permissions: {{contents: read}}\n"
                        "    steps:\n      - uses: actions/checkout@v4\n" + "{setup}" + "      - run: npm test\n")
        report = scan({WF: unprivileged.format(setup="")}, {WF: unprivileged.format(setup=cached)})
        self.assertEqual([f for f in report["findings"] if f["rule"] == "WF012"], [])

    def test_a_release_workflow_counts_even_without_declared_privileges(self):
        workflow = ("on:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: actions/checkout@v4\n{setup}      - run: ./gradlew publish\n")
        setup = "      - uses: actions/setup-java@v4\n        with:\n          cache: gradle\n"
        found = [f for f in scan({WF: workflow.format(setup="")}, {WF: workflow.format(setup=setup)})["findings"]
                 if f["rule"] == "WF012"]
        self.assertEqual(len(found), 1)
        self.assertIn("in a workflow that runs on tag pushes", found[0]["message"])
        # A CI workflow that also runs on branches and tags is not a release workflow.
        ci = workflow.replace("    tags: ['v*']", "    branches: [main]\n    tags: ['v*']")
        self.assertEqual([f for f in scan({WF: ci.format(setup="")}, {WF: ci.format(setup=setup)})["findings"]
                          if f["rule"] == "WF012"], [])

    def test_a_cache_in_a_local_composite_action_is_reported_there(self):
        action = ("runs:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v4\n      with:\n"
                  "        cache: pnpm\n")
        plain = "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
        setup = "      - uses: ./.github/actions/setup\n"
        base = {WF: self.JOB.format(extra="      id-token: write\n", setup=setup), ACTION: plain}
        head = {WF: self.JOB.format(extra="      id-token: write\n", setup=setup), ACTION: action}
        found = [f for f in scan(base, head)["findings"] if f["rule"] == "WF012"]
        self.assertEqual([(f["file"], f["workflow"]) for f in found], [(ACTION, WF)])


class CheckoutCredentials(unittest.TestCase):
    """WF013: a checkout stops setting persist-credentials: false."""
    JOB = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {perms}\n    steps:\n"
           "      - uses: actions/checkout@{version}\n{options}      - run: make\n")
    OFF = "        with:\n          persist-credentials: false\n"

    def found(self, base_options, head_options, perms="{contents: write}", version="v4", head_version=None):
        base = self.JOB.format(perms=perms, version=version, options=base_options)
        head = self.JOB.format(perms=perms, version=head_version or version, options=head_options)
        return [f for f in scan({WF: base}, {WF: head})["findings"] if f["rule"] == "WF013"]

    def test_removing_the_safeguard_is_reported(self):
        for head in ("", "        with:\n          persist-credentials: true\n",
                     "        with:\n          persist-credentials: ${{ inputs.persist }}\n"):
            with self.subTest(head=head):
                found = self.found(self.OFF, head)
                self.assertEqual(len(found), 1)
                self.assertIn(".git/config", found[0]["message"])

    def test_checkout_v6_keeps_credentials_outside_the_workspace(self):
        found = self.found(self.OFF, "", version="v6")
        self.assertIn("outside the workspace", found[0]["message"])

    def test_a_read_only_token_is_not_worth_reporting_unless_a_custom_token_is_used(self):
        self.assertEqual(self.found(self.OFF, "", perms="{contents: read}"), [])
        custom = "        with:\n          token: ${{ secrets.BOT_PAT }}\n"
        found = self.found(self.OFF + "          token: ${{ secrets.BOT_PAT }}\n", custom, perms="{contents: read}")
        self.assertEqual(len(found), 1)
        self.assertIn("custom token", found[0]["message"])

    def test_new_checkouts_and_unchanged_safeguards_are_quiet(self):
        self.assertEqual(self.found("", ""), [])
        self.assertEqual(self.found(self.OFF, self.OFF, head_version="v5"), [])
        # Checkout v1 did not keep the token.
        self.assertEqual(self.found(self.OFF, "", version="v1"), [])
