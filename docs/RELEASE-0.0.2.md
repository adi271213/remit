# 0.0.2 release checks

Evaluated runtime: `edd446b3273f53c5b3fa7cda9d45bc62cfbc8d9f`. Package and module versions agree at 0.0.2.
This patch preserves runner label/group combinations across matrix rows, including
changes that leave the combined labels and groups unchanged. Read-permission
increases continue to suggest review. Earlier release tags remain unchanged.

- [Candidate CI](https://github.com/adi271213/workflow-privilege-check/actions/runs/40306339171)
  passed 132 tests on each Python 3.11–3.14 and eight disconnected-network outcomes.
- [Hosted outcome contract](https://github.com/adi271213/workflow-privilege-check/actions/runs/40306339508)
  passed all 20 jobs, including complete, incomplete, error, missing-input,
  bounded-alias, partial-secret and Git-provenance cases in both modes.
- Thirteen consumer PR cases below passed in both modes (26 outcomes). Logs
  verified the downloaded SHA, exact input commits, read-only token permissions,
  rule facts, report consistency and expected step outcomes.
- The built wheel installed into a fresh environment without an index. The source
  distribution rebuilt and installed without an index. Installed CLI checks
  retained aliased grants, detected changed matrix combinations and stayed quiet
  for equivalent matrix rows; package and module versions matched.
- All 74 hash-verified historical reports remain unchanged, preserving 45 labeled
  legacy facts and 62 complete / 12 incomplete reports. This selected,
  self-labeled replay is not production precision/recall.

| Consumer case | Analysis / review / findings | Both-mode evidence |
|---|---|---|
| alias-neutral | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307150053) |
| alias-token | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307146998) |
| alias-runner | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307147137) |
| alias-environment | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307147732) |
| alias-dynamic-secret | incomplete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307147979) |
| alias-cycle | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307148652) |
| labels-correlation | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307150914) |
| groups-correlation | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307148415) |
| equivalent-targets | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307146794) |
| literal-alternatives | complete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307146365) |
| hosted-label-update | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307148500) |
| incomplete-with-token | incomplete / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307148818) |
| invalid-runner-with-token | error / suggested / 1 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40307148098) |

The exact-head guard rejected moving refs during the initial batch fixture update.
Final cases used a fixed base with matching PR refs; the guard was retained.
Invalid fixture files can also receive GitHub's own workflow-validation failures;
the listed consumer jobs check the analyzer's handling of those files as data.
Fixtures are never dispatched or merged.

Final main CI and released-tag installation checks are recorded in the
[release notes](https://github.com/adi271213/workflow-privilege-check/releases/tag/v0.0.2).
At publication, no fresh fork test or independent human security audit was claimed.
[Post-release fork verification](FORK-VALIDATION.md) subsequently tested the current
setup with this runtime on 2026-10-28; it is separate from the original release checks.
Runner/environment associations across matrix rows remain outside the independent
comparisons; see [known limitations](KNOWN-LIMITATIONS.md).
