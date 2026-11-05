# Changelog

## Unreleased

- **Fewer WF010 false positives, clearer advice.** A pull request checkout that
  puts only documentation in the workspace (non-cone sparse checkout of README
  or Markdown files) is no longer reported when no later step in the job runs a
  script or a local action. In audit runs on 60 repositories this removed two
  findings, both in one project that uses the pattern on purpose, and nothing
  else. WF010's message now says that pull request code in these workflows
  shares the default branch's Actions cache even without secrets.
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
