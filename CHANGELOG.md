# Changelog

## Unreleased

## 1.0.0 — 2026-11-04

First public release.

- **Eight rules** for privilege changes between a pull request's base and head:
  token scope increases (WF001), jobs relying on or leaving the repository's
  default token permissions (WF002), review-sensitive triggers such as
  `pull_request_target` (WF003), new secret references and forwarding (WF004),
  self-hosted, custom or group runners (WF005), environment changes (WF007),
  runner/environment re-pairing in matrices (WF008), and new third-party code
  in a privileged job (WF009).
- **Reports** as pull request annotations on the line that introduced each
  finding, a Markdown job summary with a review question per rule, JSON, and
  SARIF for GitHub code scanning.
- **GitHub Action** with `advisory` and `require-complete` modes. Findings never
  fail the step; incomplete or failed analysis is reported explicitly.
- **Safe on untrusted pull requests:** the head is read as Git data and never
  executed, the analysis makes no network calls, and the Action ships a
  hash-verified PyYAML bundle. Git reads ignore caller redirection and
  replacement refs, and YAML anchors are bounded before parsing.
- **CLI** `remit` on PyPI, for directories or local Git commits.
- **Validation:** the test suite on Python 3.11–3.14, an end-to-end Action run
  with networking disabled, a hosted contract of 17 cases in both modes, a
  replay of 74 historical public PRs, and a reproducible comparison with zizmor.

Tags named `v0.x` in this repository are earlier development snapshots and are
not supported.
