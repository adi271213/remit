"""Scanner correctness: eight defects found in an outside review, each with nearby controls."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from remit.conditions import excludes_pull_request_runs  # noqa: E402
from remit.scan import audit, compare  # noqa: E402
from remit.sources import directory, git_snapshot  # noqa: E402

WF = ".github/workflows/ci.yml"
ACTION = ".github/actions/setup/action.yml"
HEAD_SHA = "${{ github.event.pull_request.head.sha }}"
PRT = "on: pull_request_target\npermissions: {contents: read}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
WRITE_JOB = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    permissions: {contents: write}\n    steps:\n"
RISKY = "runs:\n  using: composite\n  steps:\n    - uses: evil/action@v1\n"
BENIGN = "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"


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


def audited(files):
    with tempfile.TemporaryDirectory() as temp:
        write(Path(temp), files)
        return audit(directory(Path(temp)))


def rules(report, *wanted):
    return [f["rule"] for f in report["findings"] if f["rule"] in wanted]


def git_repo(root, commits):
    """A repository at root with one commit per files mapping."""
    def run(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    root.mkdir(parents=True, exist_ok=True)
    run("init", "-q")
    run("config", "user.email", "test@example.com")
    run("config", "user.name", "test")
    for number, files in enumerate(commits):
        write(root, files)
        run("add", "-A")
        run("commit", "-qm", f"commit {number}")


class BranchCreation(unittest.TestCase):
    """1. Naming a new branch after the pull request does not bring its code in."""

    def pwn(self, steps):
        return rules(audited({WF: PRT + steps}), "WF010", "WF011")

    def test_creating_a_branch_is_quiet(self):
        for steps in (
                "    env:\n      NEW_BRANCH: backport-${{ github.head_ref }}\n    steps:\n"
                "      - run: git checkout -b \"$NEW_BRANCH\"\n",
                "    steps:\n      - run: git checkout -b \"bp-${{ github.head_ref }}\"\n",
                "    steps:\n      - run: git switch -c bp-${{ github.event.pull_request.head.ref }} && make\n",
                "    steps:\n      - run: git checkout -B \"bp-${{ github.head_ref }}\"\n",
                "    steps:\n      - run: git switch --orphan=\"bp-${{ github.head_ref }}\"\n"):
            with self.subTest(steps=steps):
                self.assertEqual(self.pwn(steps), [])

    def test_start_points_fetches_and_later_commands_are_still_reported(self):
        for steps in (
                f"    steps:\n      - run: git checkout -b pr {HEAD_SHA}\n",
                "    env:\n      BR: ${{ github.head_ref }}\n    steps:\n"
                "      - run: git checkout -b local \"origin/$BR\"\n",
                f"    steps:\n      - run: git checkout -b x && git reset --hard {HEAD_SHA}\n",
                "    steps:\n      - run: git checkout ${{ github.head_ref }}\n",
                "    steps:\n      - run: gh pr checkout ${{ github.event.pull_request.number }} -b review\n"):
            with self.subTest(steps=steps):
                self.assertEqual(len(self.pwn(steps)), 1)


class CompositeEnvironmentWrites(unittest.TestCase):
    """2. $GITHUB_ENV writes inside a composite action reach the caller's later steps."""
    CHECKOUT = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ env.REF }}\n"

    def action(self, value, extra=""):
        return ("runs:\n  using: composite\n  steps:\n"
                f"    - run: echo \"REF={value}\" >> \"$GITHUB_ENV\"\n      shell: bash\n{extra}")

    def pwn(self, files):
        return rules(audited(files), "WF010")

    def test_a_pull_request_value_written_in_the_action_reaches_the_caller(self):
        workflow = PRT + "    steps:\n      - uses: ./.github/actions/setup\n" + self.CHECKOUT
        self.assertEqual(self.pwn({WF: workflow, ACTION: self.action(HEAD_SHA)}), ["WF010"])

    def test_nested_composites_pass_it_up(self):
        outer = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n"
        workflow = PRT + "    steps:\n      - uses: ./.github/actions/setup\n" + self.CHECKOUT
        files = {WF: workflow, ACTION: outer, ".github/actions/inner/action.yml": self.action(HEAD_SHA)}
        self.assertEqual(self.pwn(files), ["WF010"])

    def test_an_overwrite_in_the_action_clears_it(self):
        workflow = (PRT + f"    env:\n      REF: {HEAD_SHA}\n    steps:\n      - uses: ./.github/actions/setup\n"
                    + self.CHECKOUT)
        self.assertEqual(self.pwn({WF: workflow, ACTION: self.action("main")}), [])

    def test_step_level_env_inside_the_action_does_not_leak(self):
        action = ("runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
                  f"      env:\n        REF: {HEAD_SHA}\n")
        workflow = PRT + "    steps:\n      - uses: ./.github/actions/setup\n" + self.CHECKOUT
        self.assertEqual(self.pwn({WF: workflow, ACTION: action}), [])

    def test_an_action_that_writes_nothing_leaves_the_caller_unchanged(self):
        workflow = (PRT + f"    env:\n      REF: {HEAD_SHA}\n    steps:\n      - uses: ./.github/actions/setup\n"
                    + self.CHECKOUT)
        self.assertEqual(self.pwn({WF: workflow, ACTION: BENIGN}), ["WF010"])


class InputDefaults(unittest.TestCase):
    """3. Declared input defaults apply when the caller omits the input."""

    def action(self, default):
        return (f"inputs:\n  ref:\n    default: {default}\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@v4\n      with:\n        ref: ${{ inputs.ref }}\n")

    def pwn(self, files):
        return rules(audited(files), "WF010")

    def test_a_dangerous_default_is_reported(self):
        workflow = PRT + "    steps:\n      - uses: ./.github/actions/setup\n"
        self.assertEqual(self.pwn({WF: workflow, ACTION: self.action(HEAD_SHA)}), ["WF010"])

    def test_a_safe_default_is_quiet(self):
        workflow = PRT + "    steps:\n      - uses: ./.github/actions/setup\n"
        self.assertEqual(self.pwn({WF: workflow, ACTION: self.action("main")}), [])

    def test_an_explicit_input_overrides_the_default(self):
        safe = PRT + "    steps:\n      - uses: ./.github/actions/setup\n        with:\n          ref: main\n"
        self.assertEqual(self.pwn({WF: safe, ACTION: self.action(HEAD_SHA)}), [])
        risky = (PRT + "    steps:\n      - uses: ./.github/actions/setup\n        with:\n"
                 f"          REF: {HEAD_SHA}\n")
        self.assertEqual(self.pwn({WF: risky, ACTION: self.action("main")}), ["WF010"])

    def test_reusable_workflow_defaults_apply_too(self):
        called = ("on:\n  workflow_call:\n    inputs:\n      ref:\n        type: string\n"
                  f"        default: {HEAD_SHA}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                  "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ inputs.ref }}\n")
        caller = "on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n"
        self.assertIn("WF010", rules(audited({WF: caller, ".github/workflows/called.yml": called}), "WF010"))


class RenamedWorkflows(unittest.TestCase):
    """4. A renamed workflow is compared with its old self, local code included."""
    WORKFLOW = WRITE_JOB + "      - uses: ./.github/actions/setup\n"

    def test_a_rename_does_not_hide_a_changed_action(self):
        report = scan({WF: self.WORKFLOW, ACTION: BENIGN},
                      {".github/workflows/renamed.yml": self.WORKFLOW, ACTION: RISKY})
        self.assertEqual(rules(report, "WF009"), ["WF009"])
        self.assertEqual(report["renames"], [{"before": WF, "after": ".github/workflows/renamed.yml"}])

    def test_a_rename_with_unchanged_code_is_quiet(self):
        report = scan({WF: self.WORKFLOW, ACTION: RISKY}, {".github/workflows/renamed.yml": self.WORKFLOW, ACTION: RISKY})
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["examinedFiles"], [])


class ConditionOperands(unittest.TestCase):
    """5. && and || return an operand, as in GitHub, not a boolean."""
    PUSH = "github.event.workflow_run.event == 'push'"

    def test_the_reported_counterexample_no_longer_hides_runs(self):
        self.assertFalse(excludes_pull_request_runs(f"({self.PUSH} || 'x') != true"))

    def test_operand_values_are_kept(self):
        for condition in (f"({self.PUSH} && 'x') == false", f"({self.PUSH} || false) == false",
                          f"{self.PUSH} || 'x'", f"{self.PUSH} || 1 == '1'", f"{self.PUSH} || contains(a, 'b')"):
            with self.subTest(condition=condition):
                self.assertFalse(excludes_pull_request_runs(condition))

    def test_conditions_that_do_exclude_pull_requests_still_do(self):
        for condition in (self.PUSH, f"contains(github.event.workflow_run.head_branch, 'x') && {self.PUSH}",
                          f"{self.PUSH} && contains(a, 'b')", f"{self.PUSH} && 'x'",
                          f"{self.PUSH} || github.event_name == 'workflow_dispatch'"):
            with self.subTest(condition=condition):
                self.assertTrue(excludes_pull_request_runs(condition))


class AtInLocalPaths(unittest.TestCase):
    """6. A local action path is read whole; @ does not start a ref there."""
    WORKFLOW = WRITE_JOB + "      - uses: ./actions/@scope/publish\n"

    def test_directory_mode_reads_the_full_path(self):
        base = {WF: self.WORKFLOW, "actions/action.yml": BENIGN, "actions/@scope/publish/action.yml": BENIGN}
        head = {**base, "actions/@scope/publish/action.yml": RISKY}
        self.assertEqual(rules(scan(base, head), "WF009"), ["WF009"])

    def test_a_decoy_at_the_truncated_path_is_not_read(self):
        base = {WF: self.WORKFLOW, "actions/action.yml": BENIGN, "actions/@scope/publish/action.yml": BENIGN}
        head = {**base, "actions/action.yml": RISKY}
        self.assertEqual(rules(scan(base, head), "WF009"), [])

    def test_git_mode_reads_the_full_nested_path(self):
        base = {WF: self.WORKFLOW, "actions/action.yml": BENIGN, "actions/@scope/publish/action.yml": BENIGN}
        with tempfile.TemporaryDirectory() as temp:
            git_repo(Path(temp), [base, {"actions/@scope/publish/action.yml": RISKY}])
            report = compare(git_snapshot(temp, "HEAD~1"), git_snapshot(temp, "HEAD"))
        self.assertEqual(rules(report, "WF009"), ["WF009"])


class MultipleCheckouts(unittest.TestCase):
    """7. One checkout keeping persist-credentials: false cannot hide another dropping it."""
    OFF = "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
    PLAIN = "      - uses: actions/checkout@v4\n"
    MAKE = "      - run: make\n"

    def wf013(self, base_steps, head_steps):
        return rules(scan({WF: WRITE_JOB + base_steps}, {WF: WRITE_JOB + head_steps}), "WF013")

    def test_the_second_of_two_checkouts_dropping_it_is_reported(self):
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.OFF, self.OFF + self.MAKE + self.PLAIN), ["WF013"])
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.OFF, self.PLAIN + self.MAKE + self.OFF), ["WF013"])

    def test_unchanged_added_and_removed_checkouts_are_quiet(self):
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.OFF, self.OFF + self.MAKE + self.OFF), [])
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.PLAIN, self.OFF + self.MAKE + self.PLAIN), [])
        self.assertEqual(self.wf013(self.OFF + self.MAKE, self.OFF + self.MAKE + self.PLAIN), [])
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.OFF, self.OFF + self.MAKE), [])


class LiteralGitPaths(unittest.TestCase):
    """8. Git mode reads exactly the path named, like directory mode."""
    REAL = ".github/actions/real/action.yml"

    def test_pathspec_magic_and_wildcards_select_nothing(self):
        files = {WF: "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n", self.REAL: "REAL\n"}
        with tempfile.TemporaryDirectory() as temp:
            git_repo(Path(temp), [files])
            snapshot = git_snapshot(temp, "HEAD")
            self.assertEqual(snapshot.read(self.REAL), "REAL\n")
            for path in (":/" + self.REAL, ":(glob).github/actions/*/action.yml", ":(icase).GITHUB/actions/REAL/action.yml",
                         ".github/actions/*/action.yml", ".github/actions/re?l/action.yml",
                         ".github/actions/[r]eal/action.yml"):
                with self.subTest(path=path):
                    self.assertIsNone(snapshot.read(path))

    def test_literal_names_with_special_characters_match_directory_mode(self):
        files = {WF: "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n",
                 ".github/actions/a*b/action.yml": "STAR\n", ".github/actions/a?b/action.yml": "QUESTION\n",
                 ".github/actions/[x]/action.yml": "BRACKET\n", ".github/actions/axb/action.yml": "DECOY\n"}
        with tempfile.TemporaryDirectory() as temp:
            git_repo(Path(temp, "repo"), [files])
            write(Path(temp, "dir"), files)
            in_git, in_dir = git_snapshot(Path(temp, "repo"), "HEAD"), directory(Path(temp, "dir"))
            for path in (".github/actions/a*b/action.yml", ".github/actions/a?b/action.yml",
                         ".github/actions/[x]/action.yml", ".github/actions/x/action.yml"):
                with self.subTest(path=path):
                    self.assertEqual(in_git.read(path), in_dir.read(path))
            self.assertEqual(in_git.read(".github/actions/a*b/action.yml"), "STAR\n")


if __name__ == "__main__":
    unittest.main()
