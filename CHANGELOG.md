# Changelog

## Unreleased

## 0.1.0 — 2026-11-04

- **Renamed to Remit.** The package and command are now `remit` (`pip install
  remit`, `remit scan …`); `workflow-privilege-check` remains as a command
  alias. The repository moves to `adi271213/remit`, and GitHub redirects the
  old URLs. The Python module is `remit`.
- **New rule WF002:** a new job, or a job that drops its `permissions` block,
  relying on the repository's default token permissions is now a finding that
  asks for explicit permissions. Previously it made the analysis `incomplete`,
  which failed the default `require-complete` mode on ordinary "add a workflow"
  PRs. A job that moves from inherited to explicit permissions is compared with
  GitHub's narrowest default (`contents: read`, `packages: read`): hardening
  changes stay quiet, and anything above it is a WF002 finding. In the 74-PR
  replay, all reports are now complete (previously 12 were incomplete).
- **New rule WF009:** an action or reusable workflow from outside the repository
  that newly runs in a job with write scopes, OIDC, secrets or an environment.
  Ref-only changes and GitHub-owned or local actions are quiet. 8 findings in the
  74-PR replay.
- **SARIF output:** `--format sarif` and `--sarif FILE` in the CLI, and a
  `sarif-path` Action output for uploading to GitHub code scanning. Validated
  against the SARIF 2.1.0 schema; fingerprints don't change when lines move.
- **zizmor comparison:** `scripts/compare_zizmor.py` measures which findings
  zizmor's new-findings view would also surface (26 of 69 in the replay).
- **Pull request annotations:** each finding records the head `line` that
  introduced it, and the Action shows up to 10 findings as annotations in the
  PR's Files changed tab. Annotation text is escaped, and the JSON report is
  printed with workflow commands disabled.
- Markdown reports show one WF001 row per job, so `write-all` is one row
  instead of eighteen; JSON still has one finding per scope.
- Support the `models` token permission scope. Previously any change to a
  workflow declaring `models: read` produced an analysis error.
- Markdown reports group findings under one heading per workflow file and show
  `unavailable` instead of `None` when no commit was resolved.
- 45-line install template; the separate result-explanation step is replaced by
  the Action's own annotations and notices.
- The repository runs its own Action on every PR, loaded from the base commit.
- CI lints with ruff. A release workflow publishes to PyPI with hash-pinned
  build tools and trusted publishing.
- Regenerate the stale sample JSON report and test that both samples match the
  current output.
- Consolidate documentation into README, SETUP, docs/RULES.md and
  docs/ARCHITECTURE.md. Release evidence belongs in GitHub release notes;
  earlier evidence files remain in Git history.

## 0.0.4 — 2026-10-30

- **Fix:** hyphenated property names such as `inputs.use-secrets` were split, so
  they could be mistaken for a whole-`secrets` reference. In the base, that could
  hide a newly added `secrets.DEPLOY_KEY` and return `complete / none`; in the
  head, it produced a false WF004. Versions up to 0.0.3 are affected.
- Resolve hyphenated matrix fields (`matrix.runner-name`) for runner and
  environment comparisons, including WF008. Older versions report these as
  incomplete.
- Hosted contract fixtures live in `tests/hosted_cases.json` and are built
  locally, removing the dependency on a separate test repository.

## 0.0.3 — 2026-10-30

- Add **WF008**: a new runner/environment pairing in a static matrix while the
  individual runner and environment sets stay the same. Version 0.0.2 misses
  this, e.g. swapping `production` and `staging` between a hosted and a
  self-hosted runner.
- Matrix field names resolve case-insensitively; case-only duplicates are
  incomplete.
- Markdown reports group findings by workflow and job, show before/after values,
  and include a review question per rule. Long values are shortened (JSON keeps
  them in full).
- Clearer setup-workflow errors for invalid input, fetch failures and moving PR
  heads. Source distributions include what is needed to run the test suite.

## 0.0.2 — 2026-10-26

- **Fix:** WF005 compared the union of matrix labels and groups, so it missed a
  change that rearranged label/group combinations between rows. Version 0.0.1 is
  affected. Each row's combination is now compared and included in the finding.
- Recognise `ubuntu-22.04-arm`, `windows-11-vs2026-arm` and `xcode-27` as hosted
  runner labels.

## 0.0.1 — 2026-10-26

- Support YAML anchors and aliases, bounded by limits on the whole composed
  graph. Cycles, over-limit expansion and merge keys are errors.
- Read-only permission increases (`none` → `read`) are reported by WF001.

## 0.0.0

Initial release.

- WF001 token scope increases, WF003 sensitive triggers, WF004 secret
  references, WF005 runner and WF007 environment changes.
- Bounded static matrix resolution with recorded assumptions for unresolved
  values.
- Bundled, hash-verified pure-Python PyYAML; no runtime installation.
- `advisory` and `require-complete` Action modes. Findings never fail the step.
- 74-PR historical replay with hash-pinned inputs.
