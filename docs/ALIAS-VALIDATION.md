# Bounded-alias validation before 0.0.1

Evaluated Action runtime: `3366fd4e201a1b672408fe93fd7cde2d06912362`.
At this validation, alias support was unreleased. It is included in 0.0.1;
the `v0.0.0` tag is unchanged. See [release checks](RELEASE-0.0.1.md).

- [Candidate CI](https://github.com/adi271213/workflow-privilege-check/actions/runs/40219337123)
  passed 127 tests on each of Python 3.11–3.14. Both Action modes also ran as an
  unprivileged process without network access, retaining grants in both aliased jobs.
- [Hosted contract](https://github.com/adi271213/workflow-privilege-check/actions/runs/40219363991)
  passed all 20 jobs. Valid aliases are now a supported case; malformed YAML is a
  separate error case. Existing missing-input, partial-secret and Git provenance
  regressions remain covered in both modes.
- All 21 same-repository consumer cases below passed with the pinned composite
  Action in both modes (42 outcomes). Logs verified downloaded SHA, exact base/head,
  read-only token, findings, report consistency and expected step outcomes.
- The hash-verified 74-PR replay retains all 45 legacy facts, 62 complete and 12
  incomplete reports. Every report is identical to the 0.0.0 replay. The packet has
  no alias-driven cases; it demonstrates regression preservation, not an observed
  completeness improvement. It remains selected and self-labeled.

Run `python scripts/validate.py` for the local suite. Its checked-in
`tests/alias_cases.json` contains the 21 base/head fixtures and expected rules.
Tests compare ordinary aliased inputs against equivalent fully inlined documents,
check limits at their boundaries, assert rejection before object construction,
retain independent findings across files, and time-bound hostile inputs in a fresh
process. The [YAML policy](YAML-POLICY.md) defines the bounds and unsupported inputs.

| Consumer case | Analysis / review / findings | Both-mode evidence |
|---|---|---|
| alias-neutral | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219587704) |
| alias-permissions | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219565473) |
| alias-token | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219575149) |
| alias-secret | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219594330) |
| alias-runner | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219541785) |
| alias-environment | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219526695) |
| alias-matrix | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219551265) |
| alias-dynamic-secret | incomplete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219585661) |
| alias-unknown-base-secret | incomplete / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219565172) |
| alias-dynamic-runner | incomplete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219539658) |
| alias-dynamic-environment | incomplete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219526750) |
| alias-merge-key | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219574498) |
| alias-undefined | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219581071) |
| alias-duplicate-anchor | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219539202) |
| alias-cycle | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219576523) |
| alias-hidden-bomb | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219552057) |
| alias-matrix-bomb | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219581112) |
| alias-scalar-bomb | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219554385) |
| alias-count-limit | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219521085) |
| alias-syntax-error | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219564385) |
| alias-mapping-key | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40219578648) |

Invalid fixture files can also receive GitHub's own workflow-validation failures;
the listed consumer jobs independently verify the Action's handling of their data.
Fixtures were never dispatched or merged. No current-version fork run, independent
human security audit, production precision/recall or maintainer usefulness is claimed.
Read-only permission increases continue to suggest review.
