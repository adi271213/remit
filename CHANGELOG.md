# Changelog

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
- **CLI** `remit` on PyPI, for directories or local Git commits.
- **Validation:** the test suite on Python 3.11–3.14, an end-to-end Action run
  with networking disabled, a hosted contract of 18 cases in both modes, a
  replay of 74 historical public PRs, and a reproducible comparison with zizmor.
