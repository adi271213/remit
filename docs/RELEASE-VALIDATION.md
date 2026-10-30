# 0.0.0 release validation (historical)

Evaluated Action source: `11e29536ed91edf93c00e94f0bf178a5fca759dd`.
Later setup/evidence commits retain identical runtime, tests and bundled dependency.

- [CI](https://github.com/adi271213/workflow-privilege-check/actions/runs/40208783607)
  passed 117 tests on each of Python 3.11–3.14. Each job also exercised both modes
  with the actual Action controller in a disconnected network namespace: eight
  network-isolated outcomes. Dependency files are bundled, never installed at runtime.
- [Mode contract](https://github.com/adi271213/workflow-privilege-check/actions/runs/40208798869) passed all 18 jobs,
  including expected require-complete failures, missing inputs, partial secrets
  and Git provenance regressions.
- All 15 same-repository consumer installation checks below passed. Logs verified
  the downloaded Action SHA, exact event inputs, read-only permissions, structured
  reports, and expected analysis/review states. Fixtures were data, not executed.
- All 1,095 unique public blobs in the 74-PR manifest were fetched independently
  from its published URLs and hash-verified. The fresh-cache offline replay
  preserved all 45 legacy facts and 62 complete / 12 incomplete results, adding
  one WF007 finding. New-rule usefulness/accuracy is not independently adjudicated.
- A built wheel and source metadata both identify version 0.0.0.

| Consumer case | Analysis / review / findings | Evidence |
|---|---|---|
| neutral | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208944960) |
| runner-self-hosted | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208947812) |
| runner-matrix | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208951537) |
| runner-dynamic | incomplete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208956198) |
| environment-add | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208959047) |
| environment-change | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208963812) |
| environment-remove | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208970076) |
| environment-dynamic | incomplete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208972794) |
| environment-url-only | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208976869) |
| all-four-triggers | complete / suggested / 4 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208981108) |
| incomplete | incomplete / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208983951) |
| alias-error | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208986360) |
| syntax-error | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208991154) |
| token-write | complete / suggested / 3 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208996352) |
| source-override | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40208999404) |

The deliberate malformed fixture also received GitHub's own YAML validation
failure; the listed consumer check separately verified correct error reporting.
No current-version fork or rendered-UI assertion is claimed. Earlier genuine
fork tests remain historical evidence only. There is no production precision or
recall estimate, independent human security audit, or maintainer usefulness result.
Synthetic tests and replay commands
are documented in [VALIDATION.md](../VALIDATION.md).
