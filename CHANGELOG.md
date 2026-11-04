# Changelog

## Unreleased

- Support the `models` token permission scope (`none`/`read`). Previously any
  change to a workflow declaring `models: read` produced an analysis error.
- Markdown reports group findings under one heading per workflow file and show
  `unavailable` instead of `None` when no commit was resolved.
- Regenerate the stale sample JSON report and test that both samples match the
  current output.
- Consolidate documentation into README, SETUP, docs/RULES.md and
  docs/ARCHITECTURE.md. Release verification evidence belongs in GitHub release
  notes from now on; earlier evidence files remain in Git history.

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
