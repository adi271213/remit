# Changes

## Unreleased

## 0.0.4 — 2026-10-30

- Fix expression identifier boundaries: hyphenated properties such as
  `inputs.use-secrets` no longer invent whole-secret access or hide a newly
  added literal secret reference. Preserve complete literal property names.
- Resolve hyphenated direct matrix fields for runner/environment comparisons,
  including WF008 associations; retain existing uncertainty for dynamic values.
- Store hosted contract fixtures in this repository and create their Git objects
  locally. Add identifier regressions to the hosted contract and isolated smoke
  test; remove the contract's dependency on the disposable pilot repository.
- Correct the 0.0.3 evidence count: six isolated outcomes per Python version,
  24 across its four-version matrix. Its separate hosted contract had 24 jobs.

## 0.0.3 — 2026-10-30

- Add WF008 for new runner/environment pairings in bounded static matrices when
  individual target sets stay unchanged. Retain row bindings as evidence and
  report changed unresolved associations as incomplete.
  Normalize equivalent selector forms before assessing association uncertainty.
- Resolve direct matrix variable names case-insensitively. Treat conflicting
  duplicate field names as incomplete instead of selecting an arbitrary value.

- Group Markdown findings by workflow/job, show recorded before/after values and
  add rule-specific reviewer guidance. Keep unresolved analysis visible alongside
  known findings; shorten long display values without changing JSON evidence.

- Use the checked-in wheel URL and SHA-256 when refreshing the PyYAML bundle.
- Explain invalid inputs, fetch failures and moving PR heads in the setup workflow.
- Include license/source metadata and the fixtures needed to validate a source distribution.
- Clarify fork-test coverage, security reporting and contributor checks; format the
  hosted outcome contract as readable YAML without changing its job definitions.

## 0.0.2 — 2026-10-26

- Preserve runner label/group combinations when comparing matrix selections.
  Version 0.0.1 can miss changes that rearrange those combinations while leaving
  the combined labels and groups unchanged.
- Recognize three additional documented GitHub-hosted runner labels:
  `ubuntu-22.04-arm`, `windows-11-vs2026-arm` and `xcode-27`.
- Refresh generated sample reports and remove stale version/release wording.

## 0.0.1 — 2026-10-26

- Analyze bounded YAML anchors/aliases across permissions, secrets, runner and
  environment selections. Validate the whole composed graph before construction;
  reject cycles, expanded depth/node/byte limits, and unsupported merge keys.
- Keep read-only permission increases as review prompts.
- Align package/module metadata to 0.0.1 and publish a general setup guide;
  retain the advisory pilot link and feedback instructions.

## 0.0.0 — initial experimental version

- Report configured token, selected trigger and secret-reference additions.
- Add review prompts for self-hosted/custom/unresolved runner changes and
  environment target additions, removals and changes. Resolve bounded literal
  matrices; disclose uncertainty and symbolic assumptions.
- Bundle verified pure-Python PyYAML with its MIT license and provenance manifest.
  The Action performs no runtime pip install or dependency download.
- Restore the public setup guide and SHA-pinned installation; describe advisory,
  require-complete and CLI outcomes separately. Findings never enforce approval.
- Publish the hash-pinned 74-PR regression manifest and replay command, with clear
  self-labeling, selection and new-rule limits. Retain a concise public surface.
- Align package/module versions to 0.0.0. Earlier iteration tags remain historical
  references; they are not the current initial-version installation.
