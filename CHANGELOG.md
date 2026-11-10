# Changelog

## Unreleased

A follow-up review of 1.2 found gaps in three of its fixes, a slow pattern and a
crash. All were reproduced first and have regression tests with controls:

- **Commands inside a new branch's name are examined again.** 1.2 ignored the
  whole name in `git checkout -b NAME`, including a command substituted into it:
  `git checkout -b "x-$(git fetch origin $PR_REF && git checkout FETCH_HEAD)"`
  was not reported. Only the name's inert text is ignored now. The name is also
  recognised more strictly, so `-bc $REF`, `{a,$REF}` and `-b` used as another
  option's value no longer hide a reference.
- **Long script lines are read in one pass.** The 1.2 branch-name filter took
  20 seconds on a 180 KB line; a fetch pattern present since version 1 had the
  same quadratic growth on repeated `git fetch`. Both are now linear, and tests
  check how time grows with input size.
- **`$GITHUB_ENV` writes in composite actions are tracked as writes.** 1.2
  compared scoped values before and after the action, so re-exporting a value
  the action was given in its step's `env:` was missed, and re-exporting a safe
  override left a stale warning.
- **WF013 matches each checkout to the same step before comparing.** Counting
  safe checkouts missed a checkout that lost `persist-credentials: false` when
  a safe one was added elsewhere, and falsely reported one when a safe checkout
  was deleted. Steps are matched by `id`, then by their place among unchanged
  steps; pairs that can't be told apart are reported as ambiguous.
- **Long conditions no longer crash.** An `if:` with 1,200 `||` terms ended the
  run with a Python error and no report. Chains are evaluated in a loop, nesting
  and size have budgets beyond which a condition rules nothing out, and the
  command line reports an input that nests too deeply instead of crashing.
- **More fetches are recognised.** `git -C dir fetch …` (options before the
  subcommand) and a command continued on the next line with a backslash were
  not read as fetches or checkouts of the reference they name.

## Version 1.2 — 2026-11-10

Fixes for eight scanner defects found in an outside review. Each one was
reproduced first and has a regression test with nearby controls:

- **WF010 false positive on new branches.** `git checkout -b "$NEW_BRANCH"` (or
  `-B`, `git switch -c`/`-C`, `--orphan`) with a branch name built from pull
  request data was reported, though it only names a branch at the current
  commit. The name is no longer examined; a pull request start point after it,
  and later commands on the line, still are.
- **`$GITHUB_ENV` writes in composite actions now reach the caller.** A pull
  request value a local composite action writes to `$GITHUB_ENV` was lost when
  the action returned, so a later checkout using it was missed.
- **Input defaults apply.** A composite action's or reusable workflow's input
  `default` is used when the caller omits the input; an explicit input still
  takes precedence.
- **Renamed workflows are compared with their old path.** A workflow renamed
  without changes hid changes to the local actions it uses.
- **`&&` and `||` return an operand, as in GitHub.** `(... == 'push' || 'x') != true`
  was read as excluding pull request runs; it is always true.
- **Local action paths keep `@`.** `./actions/@scope/publish` was read as
  `./actions/`, so another action could stand in for the one that runs.
- **WF013 with several checkouts.** One checkout that kept
  `persist-credentials: false` hid another of the same repository and path
  that dropped it. Checkouts are now counted.
- **Git mode reads paths literally.** Git pathspec syntax (`:/`, `:(glob)`,
  wildcards) in a referenced path could make Remit read a different file than
  directory mode or GitHub would.

## Version 1.1 — 2026-11-05

- **Project security, continued.** CodeQL now analyses the Python code and this
  repository's workflows; coverage-guided fuzzing with Atheris runs on every pull
  request (about 100,000 inputs in two and a half minutes locally, no failures);
  and a published GitHub release gets its package files and Sigstore signatures
  attached by a workflow, so they can be traced to this repository.
- **Two new rules for controls a pull request can remove.** WF012 reports a job
  with write scopes, OIDC, secrets or an environment that newly restores files
  from the Actions cache, including a version bump that turns caching on by
  default (`actions/setup-node` v4 to v5, `actions/setup-go` v3 to v4). WF013
  reports a checkout that stops setting `persist-credentials: false` where the
  token can write or is a custom token, and says where that version keeps it.
- **Fixed: a mixed-type comparison could hide a pwn request.** In a
  `workflow_run` job's `if:`, `... == 'push' || 1 == '1'` was read as ruling out
  pull request runs, but GitHub converts both sides to numbers and the condition
  is always true. Comparisons between different types are now unknown, so they
  never silence WF010 or WF011.
- **Fixed: documentation-only checkouts were trusted too far.** A sparse
  checkout of README or Markdown files from the pull request is now quiet only
  when every later step is `actions/checkout` or `actions/upload-artifact`. Any
  other action, local or external, may render, template or run those files, so
  it is reported.
- **Fewer WF010 false positives from overwritten variables.** Replacing a pull
  request value with a fixed one (`REF: main`, `echo "REF=main" >>
  "$GITHUB_ENV"`, or `github.sha`) clears it; a replacement Remit can't resolve
  keeps it.
- **WF010 says what it saw.** The message reports the pull request content the
  job brings in and what the job has. It says the content can be executed, and
  can write to the branch's Actions cache, only when a later script or local
  action (or the fetching script itself) runs, and names that step (`runBy`).
- **Benchmark scripts: failures are no longer zeros.** The field comparison
  records a tool that crashed or printed unreadable output as failed, leaves
  that commit out of the tool's counts, and keeps Remit findings on such commits
  out of the "Remit only" total. The planted-change test counts a detection only
  when the rule, file, workflow and job all match the planted change.
- **Project security.** An OpenSSF Scorecard workflow checks the repository's
  own practices and publishes a score (README badge), and Dependabot keeps the
  pinned actions and hash-pinned tools current. The README, setup guide and
  security policy now say plainly that Remit helps reviewers and never blocks a
  merge, and recommend a `CODEOWNERS` rule for `.github/`.

From a held-out validation (30 more repositories, planted changes and fuzzing;
see `benchmarks/README.md`):

- **Fixed: slow scans on hostile input.** Three patterns that read script lines
  and expressions backtracked on long, specially shaped text: a 200 KB line in a
  pull request could take minutes, enough to time the Action out. They are now
  linear scans with identical results, checked against the old patterns on
  300,000 random strings; a 1 MB hostile line takes about 1.6 s.
- **Less WF002 noise.** Replacing the default token with a read-only block is
  hardening and no longer reported; a block with a write scope still is. A new
  job in a workflow whose jobs already used the default is quiet; the first such
  job, or a new workflow, is still reported. In the held-out repositories these
  were 41 of 55 WF002 findings.

From running Remit, zizmor, poutine and actionlint on 446 recent workflow
commits in 30 popular repositories (see `benchmarks/README.md`):

- **Less noise.** A new job's `read` scopes are no longer reported as WF001
  increases; they are narrower than any default token. This removed 62 of 279
  findings in that comparison. Six expected WF001 results in the 74-PR replay
  were of this kind and were removed from its labels. A change from an
  unresolvable runner to GitHub-hosted labels is no longer reported as WF005.
- **One finding per shared change.** A change in a shared local action or
  reusable workflow that reaches several jobs is reported once, with the jobs
  listed in a new `jobs` field.
- **Large and deep workflows.** Files up to 1 MiB are analysed (was 256 KiB),
  and a larger file no longer fails the whole run: unchanged, it is ignored;
  changed, only that file is `incomplete`. Local references are followed ten
  levels deep, GitHub's own limit (was four).
- **Checkouts in the workspace.** `uses: ./path` takes earlier
  `actions/checkout` steps into account: this repository checked out into a
  folder is followed, and an action from another checked-out repository is
  reported as third-party code instead of making the analysis incomplete.
- **Own repository by name.** With `--repository-name owner/repo` (the Action
  passes it), `owner/repo/...@branch` is the repository's own code, not WF009.
  Full-SHA self-references are still reported, since the SHA may be a fork's.
- **`workflow_run` conditions.** A job whose `if:` (or a needed job's) rules
  out runs caused by pull requests, such as
  `github.event.workflow_run.event == 'push'`, no longer gets WF010/WF011.

## Version 1 — 2026-11-04

First public release.

- **Ten rules** for privilege changes between a pull request's base and head:
  token scope increases (WF001), jobs relying on or leaving the repository's
  default token permissions (WF002), review-sensitive triggers such as
  `pull_request_target` (WF003), new secret references and forwarding (WF004),
  self-hosted, custom or group runners (WF005), environment changes (WF007),
  runner/environment re-pairing in matrices (WF008), new third-party code in a
  privileged job (WF009), pull request content brought into a
  `pull_request_target`, `workflow_run` or `issue_comment` job (WF010), and
  mutable pull request references checked out after a label, comment or
  environment approval (WF011, time-of-check to time-of-use).
- **Compares from the merge-base.** When the base comes from the pull request
  event, the Action compares from where the PR branched off, as GitHub's Files
  changed view does, so a stale branch doesn't show base-branch changes reversed.
- **Indirect references are followed:** WF010 and WF011 trace pull request
  references through environment variables, `$GITHUB_ENV`, step outputs,
  `needs` job outputs and action inputs, and treat runtime lookups such as
  `gh pr view` as pull request content. Besides checkouts, WF010 recognizes
  clones of the head repository, `gh pr diff | git apply`, archive downloads of
  the head commit, and artifact downloads with `gh run download` or
  `github-script`.
- **Comment commands count as approval only when checked:** an `issue_comment`
  job is treated as gated (WF011) only when it, or a job it needs, checks who
  commented. A check of the comment's text alone is WF010, since anyone can
  type it.
- **`remit audit`** reports WF010 and WF011 in a repository's current state,
  for a directory or any Git commit, as JSON, Markdown or SARIF, with an
  optional `--fail-on-findings` exit code for scheduled checks.
- **Local code is followed:** steps inside local composite actions and local
  reusable workflows (`./path` and `$/path`) count, and a change to them is
  caught even when no workflow file changed. A local file that can't be read or
  parsed makes the analysis `incomplete` for every job that uses it.
- **Reports** as pull request annotations on the line that introduced each
  finding (an incomplete analysis first, then the most serious rules, with a
  job's WF001 scopes combined so GitHub's 10-annotation limit doesn't hide them), a Markdown job summary with a review question per rule, JSON, and
  SARIF for GitHub code scanning.
- **GitHub Action** with `advisory` and `require-complete` modes. Findings never
  fail the step; incomplete or failed analysis is reported explicitly.
- **Safe on untrusted pull requests:** the head is read as Git data and never
  executed, the analysis makes no network calls, and the Action ships a
  hash-verified PyYAML bundle. Git reads ignore caller redirection and
  replacement refs, and YAML anchors are bounded before parsing.
- **CLI** `remit` (`pip install remit-actions`), for directories or local Git commits.
- **Validation:** the test suite on Python 3.11–3.14, an end-to-end Action run
  with networking disabled, a hosted contract of 18 cases in both modes, a
  replay of 74 historical public PRs, and a reproducible comparison with zizmor.
