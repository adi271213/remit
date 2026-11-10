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


# Follow-up review of 1.2: gaps in the fixes above, each with controls on both sides.

WRITE_PRT = "on: pull_request_target\npermissions: {contents: write}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"


class BranchNameSubstitutions(unittest.TestCase):
    """Only the inert text of a new branch's name is ignored; commands inside it run."""

    def pwn(self, script, env=f"    env:\n      PR_REF: {HEAD_SHA}\n      NAME: bp-${{{{ github.head_ref }}}}\n"):
        body = "".join(f"          {line}\n" for line in script.splitlines())
        return rules(audited({WF: WRITE_PRT + env + "    steps:\n      - run: |\n" + body}), "WF010", "WF011")

    def test_commands_substituted_into_the_name_are_examined(self):
        for script in (
                'git checkout -b "branch-$(git fetch origin $PR_REF && git checkout -q FETCH_HEAD; printf fixed)"\nmake',
                "git checkout -b `git fetch origin $PR_REF`x\nmake",
                'git checkout -b "x-$(git checkout -b "$NAME" $PR_REF)"',
                'git switch --orphan="o-$(git reset --hard $PR_REF)"',
                'git checkout -b "x-${NAME:-$(git fetch origin $PR_REF)}"'):
            with self.subTest(script=script):
                self.assertEqual(len(self.pwn(script)), 1)

    def test_words_that_only_look_like_a_branch_name_are_examined(self):
        # Each of these checks out $PR_REF: it is a start point or a tree, not the new name.
        for script in ("git checkout -bc $PR_REF",                       # -b with the name "c"
                       "git checkout -b {x,$PR_REF}",                    # brace expansion: -b x $PR_REF
                       "git checkout --pathspec-from-file -b $PR_REF",   # -b is that option's value
                       "git checkout --conflict -b $PR_REF",
                       "git --attr-source checkout clone -b $PR_REF url",  # this is git clone -b
                       "git checkout -- -b $PR_REF",
                       "git checkout -b x $PR_REF",
                       "git checkout -b x; git reset --hard $PR_REF",
                       "git fetch origin -b $PR_REF"):
            with self.subTest(script=script):
                self.assertEqual(len(self.pwn(script)), 1)

    def test_ordinary_branch_creation_stays_quiet(self):
        for script in ('git checkout -b "$NAME"', "git checkout -b $NAME", "git checkout -qb $NAME main",
                       'git switch -c "$NAME"', "git switch --create=$NAME", 'git switch --force-create "$NAME" origin/main',
                       'git -C repo checkout --track -b "$NAME" origin/main', 'sudo git checkout -q -f -B "${NAME}-fix" && make',
                       "git checkout -b 'x-$(not run)-'\"$NAME\"", 'git checkout -b "$NAME-$(date +%s)"'):
            with self.subTest(script=script):
                self.assertEqual(self.pwn(script), [])

    def test_options_between_git_and_its_subcommand_are_read(self):
        for script in ("git -C repo fetch origin $PR_REF", 'git -c "user.name=a b" checkout $PR_REF',
                       "git --git-dir=.g reset --hard $PR_REF", "git -C repo fetch origin pull/7/head",
                       'bash -c "git -C repo fetch origin $PR_REF"'):
            with self.subTest(script=script):
                self.assertEqual(len(self.pwn(script)), 1)
        # A subcommand name inside another command's message is not that command.
        for script in ('git commit -m "checkout $PR_REF"', "git log --oneline $PR_REF", 'git tag "fetch-$PR_REF"'):
            with self.subTest(script=script):
                self.assertEqual(self.pwn(script), [])

    def test_a_command_continued_on_the_next_line_is_one_command(self):
        self.assertEqual(len(self.pwn("git fetch origin \\\n  $PR_REF\ngit checkout FETCH_HEAD")), 1)
        self.assertEqual(len(self.pwn('git checkout -b "$NAME" \\\n  $PR_REF')), 1)
        self.assertEqual(self.pwn('git checkout \\\n  -b "$NAME"'), [])


class ScannerScaling(unittest.TestCase):
    """Reading a script line costs time in proportion to its length."""

    def growth(self, make):
        from remit.shell import without_new_branch_names
        import time
        timings = []
        for size in (10_000, 80_000):
            text = make(size)
            best = float("inf")
            for _ in range(3):
                start = time.perf_counter()
                without_new_branch_names(text)
                best = min(best, time.perf_counter() - start)
            timings.append(best)
        return timings[1] / max(timings[0], 1e-4)

    def test_eight_times_the_input_takes_about_eight_times_as_long(self):
        shapes = {
            "non-matching": lambda n: "git checkout main " * n,
            "matching": lambda n: 'git checkout -b "b$X"; ' * n,
            "one quoted argument": lambda n: "printf '%s' \"" + "git checkout main " * n + "\"",
            "unterminated substitutions": lambda n: "git checkout -b " + "$(" * n,
            "nested substitutions": lambda n: "git checkout -b " + "$(git checkout -b " * n + "x" + ")" * n,
            "unterminated expressions": lambda n: "git checkout -b '" + "${{ a " * n,
        }
        for name, make in shapes.items():
            with self.subTest(shape=name):
                # Linear is 8; the regular expression this replaced was near 64.
                self.assertLess(self.growth(make), 24)

    def test_the_whole_analysis_scales_with_a_repeated_command(self):
        import time
        head = ("on: pull_request_target\npermissions: {contents: write}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: '")
        base = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        for unit in ("git fetch ", "git pull ", "gh pr diff ", "git -C x ", "git checkout -b "):
            timings = []
            for count in (1_500, 12_000):
                start = time.perf_counter()
                scan({WF: base}, {WF: head + unit * count + "'\n"})
                timings.append(time.perf_counter() - start)
            with self.subTest(unit=unit):
                # "git fetch " took 56 times as long for 8 times the text before.
                self.assertLess(timings[1] / max(timings[0], 0.01), 24)

    def test_a_180_kb_script_is_analysed_quickly(self):
        import time
        body = "git checkout main " * 10_000
        workflow = ("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - run: printf '%s' \"" + body + "\"\n")
        small = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        start = time.perf_counter()
        report = scan({WF: small}, {WF: workflow})
        self.assertLess(time.perf_counter() - start, 5)
        self.assertEqual((report["analysis"], report["findings"]), ("complete", []))


class ExportedVariables(unittest.TestCase):
    """A composite action's $GITHUB_ENV writes are followed as writes, whatever the scoped values were."""
    EXPORT = ".github/actions/export/action.yml"
    WRITES = "runs:\n  using: composite\n  steps:\n    - run: echo \"PR_REF=$PR_REF\" >> \"$GITHUB_ENV\"\n      shell: bash\n"
    CHECKOUT = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ env.PR_REF }}\n      - run: make\n"

    def pwn(self, job_env, step_env, action=None, extra=None):
        steps = ("    steps:\n      - uses: ./.github/actions/export\n" + step_env + self.CHECKOUT)
        files = {WF: WRITE_PRT + job_env + steps, self.EXPORT: action or self.WRITES, **(extra or {})}
        return rules(audited(files), "WF010")

    def test_a_step_scoped_pull_request_value_is_exported(self):
        self.assertEqual(self.pwn("", f"        env:\n          PR_REF: {HEAD_SHA}\n"), ["WF010"])

    def test_through_a_nested_action_too(self):
        outer = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n"
        found = self.pwn("", f"        env:\n          PR_REF: {HEAD_SHA}\n", action=outer,
                         extra={".github/actions/inner/action.yml": self.WRITES})
        self.assertEqual(found, ["WF010"])

    def test_exporting_a_safe_override_clears_the_job_level_value(self):
        self.assertEqual(self.pwn(f"    env:\n      PR_REF: {HEAD_SHA}\n", "        env:\n          PR_REF: main\n"), [])

    def test_without_a_write_a_scoped_value_changes_nothing(self):
        self.assertEqual(self.pwn("", f"        env:\n          PR_REF: {HEAD_SHA}\n", action=BENIGN), [])
        self.assertEqual(self.pwn(f"    env:\n      PR_REF: {HEAD_SHA}\n", "        env:\n          PR_REF: main\n",
                                  action=BENIGN), ["WF010"])

    def test_a_value_is_not_known_after_a_step_that_could_have_changed_it(self):
        # SAFE is a literal, but a program or an action that isn't read may have rewritten it.
        for opaque in ("    - run: ./ci/setup.sh\n      shell: bash\n", "    - uses: some/action@v1\n",
                       "    - run: echo \"SAFE=x\" | tee -a \"$GITHUB_ENV\"\n      shell: bash\n"):
            action = ("runs:\n  using: composite\n  steps:\n" + opaque +
                      "    - run: echo \"PR_REF=$SAFE\" >> \"$GITHUB_ENV\"\n      shell: bash\n")
            with self.subTest(opaque=opaque):
                found = self.pwn(f"    env:\n      PR_REF: {HEAD_SHA}\n      SAFE: main\n", "", action=action)
                self.assertEqual(found, ["WF010"])
        direct = "runs:\n  using: composite\n  steps:\n    - run: echo \"PR_REF=$SAFE\" >> \"$GITHUB_ENV\"\n      shell: bash\n"
        self.assertEqual(self.pwn(f"    env:\n      PR_REF: {HEAD_SHA}\n      SAFE: main\n", "", action=direct), [])


class CheckoutIdentity(unittest.TestCase):
    """WF013 compares each checkout with the same step on the other side."""
    OFF = "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
    PLAIN = "      - uses: actions/checkout@v4\n"
    MAKE = "      - run: make\n"
    TEST = "      - run: make test\n"

    def wf013(self, base_steps, head_steps):
        return [f for f in scan({WF: WRITE_JOB + base_steps}, {WF: WRITE_JOB + head_steps})["findings"]
                if f["rule"] == "WF013"]

    def test_a_weakened_checkout_is_reported_even_when_a_safe_one_is_added(self):
        found = self.wf013(self.OFF + self.MAKE, self.PLAIN + self.MAKE + self.OFF)
        self.assertEqual([(f["line"], f["after"]) for f in found], [(7, {"persist-credentials": True})])

    def test_deleting_a_safe_checkout_is_not_a_weakening_of_another(self):
        self.assertEqual(self.wf013(self.PLAIN + self.MAKE + self.OFF, self.PLAIN + self.MAKE), [])
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.PLAIN, self.MAKE + self.PLAIN), [])

    def test_additions_and_unchanged_steps_are_quiet(self):
        self.assertEqual(self.wf013(self.OFF + self.MAKE, self.OFF + self.MAKE + self.PLAIN), [])
        self.assertEqual(self.wf013(self.OFF + self.MAKE, self.OFF + self.PLAIN + self.MAKE), [])
        self.assertEqual(self.wf013(self.OFF + self.MAKE + self.OFF, self.OFF + self.TEST + self.MAKE + self.OFF), [])

    def test_explicit_ids_match_across_reordering(self):
        def step(step_id, safe):
            return (f"      - uses: actions/checkout@v4\n        id: {step_id}\n"
                    + ("        with:\n          persist-credentials: false\n" if safe else ""))
        base = step("first", True) + self.MAKE + step("second", True)
        self.assertEqual(len(self.wf013(base, step("second", True) + self.MAKE + step("first", False))), 1)
        self.assertEqual(self.wf013(base, step("second", True) + self.MAKE + step("first", True)), [])

    def test_a_moved_and_weakened_checkout_is_reported_as_ambiguous(self):
        found = self.wf013(self.OFF + self.MAKE + self.TEST, self.MAKE + self.TEST + self.PLAIN)
        self.assertEqual([f["after"] for f in found], [{"persist-credentials": True, "match": "ambiguous"}])
        self.assertIn("does not set persist-credentials: false where one did before", found[0]["message"])

    def test_a_safe_copy_added_beside_the_changed_checkout_is_ambiguous(self):
        # The same text whether the old step lost the setting or an unsafe copy was put before it.
        found = self.wf013(self.OFF + self.MAKE, self.PLAIN + self.OFF + self.MAKE)
        self.assertEqual([f["after"] for f in found], [{"persist-credentials": True, "match": "ambiguous"}])

    def test_checkouts_of_different_paths_are_different_steps(self):
        side = "      - uses: actions/checkout@v4\n        with:\n          path: tools\n"
        self.assertEqual(self.wf013(self.OFF + self.MAKE, self.MAKE + side), [])

    def test_alignment_of_long_step_lists_stays_bounded(self):
        import time
        from remit.checkouts import aligned
        start = time.perf_counter()
        pairs = aligned(tuple("a" * 3000 + "b"), tuple("b" + "a" * 3000))
        self.assertLess(time.perf_counter() - start, 5)
        self.assertLessEqual(len(pairs), 3001)


class LongConditions(unittest.TestCase):
    """Chains are folded in a loop; nesting has a budget; nothing ends the run without a report."""
    PUSH = "github.event.workflow_run.event == 'push'"
    JOB = ("on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\npermissions: {{contents: write}}\n"
           "jobs:\n  j:\n    if: {condition}\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n        with:\n          ref: ${{{{ github.event.workflow_run.head_sha }}}}\n"
           "      - run: make\n")

    def audit(self, condition):
        report = audited({WF: self.JOB.format(condition=condition)})
        return report["analysis"], rules(report, "WF010")

    def test_a_long_true_chain_keeps_the_finding(self):
        self.assertEqual(self.audit(" || ".join(["true"] * 1200)), ("complete", ["WF010"]))
        self.assertEqual(self.audit(" || ".join(["true"] * 30_000)), ("complete", ["WF010"]))

    def test_a_long_chain_that_excludes_pull_requests_still_does(self):
        self.assertEqual(self.audit(" && ".join([self.PUSH] * 1200)), ("complete", []))
        self.assertEqual(self.audit(" || ".join([self.PUSH] * 1200)), ("complete", []))
        self.assertEqual(self.audit(" || ".join([self.PUSH] * 1199 + ["true"])), ("complete", ["WF010"]))

    def test_other_long_shapes(self):
        cases = {
            "!" * 1200 + "(" + self.PUSH + ")": True,
            "!" * 1201 + "(" + self.PUSH + ")": False,
            "(" * 40 + self.PUSH + ")" * 40: True,
            "(" * 60 + self.PUSH + ")" * 60: False,       # beyond the nesting budget: not evaluated
            " == ".join(["1"] * 5000): False,
            self.PUSH + " && " + " == ".join(["1"] * 5000): True,
            "contains(" * 60 + "'a'" + ", 'b')" * 60 + " && " + self.PUSH: False,
            self.PUSH + " && (" + " || ".join(["failure()"] * 2000) + ")": True,
        }
        for condition, excluded in cases.items():
            with self.subTest(condition=condition[:40]):
                self.assertIs(excludes_pull_request_runs(condition), excluded)

    def test_the_command_line_reports_instead_of_crashing(self):
        import json
        condition = " || ".join(["true"] * 1200)
        with tempfile.TemporaryDirectory() as temp:
            write(Path(temp), {WF: self.JOB.format(condition=condition)})
            run = subprocess.run([sys.executable, "-m", "remit", "audit", "--dir", temp], capture_output=True, text=True,
                                 env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"), "PATH": ""})
        self.assertEqual(run.returncode, 0, run.stderr[-300:])
        self.assertEqual([f["rule"] for f in json.loads(run.stdout)["findings"]], ["WF010"])
