# 0.0.1 release checks

Evaluated runtime: `ed5248238b1f88d06cb76e9bfa6427e09567f743`.
Package and module versions agree at 0.0.1. This release includes bounded aliases;
read-only permission increases still suggest review. The v0.0.0 tag is unchanged.

- [Candidate CI](https://github.com/adi271213/workflow-privilege-check/actions/runs/40223223486)
  passed 127 tests on each Python 3.11–3.14 and eight disconnected-network outcomes.
- [Hosted contract](https://github.com/adi271213/workflow-privilege-check/actions/runs/40223221809)
  passed all 20 jobs, including complete, incomplete, error, missing input,
  supported aliases, partial secrets and Git provenance regressions in both modes.
- Six consumer PR cases below passed in both modes (12 outcomes). Logs verified
  the downloaded SHA, exact input commits, read-only permissions, rule facts,
  report consistency and expected advisory/require-complete step outcomes.
- The wheel installed into a fresh environment without an index; the source
  distribution rebuilt and installed without an index. The installed CLI retained
  both token findings in aliased jobs and package/module metadata agreed.
- All 74 hash-verified historical reports are unchanged; all 45 labeled legacy
  facts remain, with 62 complete / 12 incomplete reports. This selected,
  self-labeled replay is not production precision/recall.

| Consumer case | Analysis / review / findings | Both-mode evidence |
|---|---|---|
| alias-neutral | complete / none / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40223280440) |
| alias-token | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40223280355) |
| alias-runner | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40223284945) |
| alias-environment | complete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40223289682) |
| alias-dynamic-secret | incomplete / suggested / 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40223293303) |
| alias-cycle | error / unknown / 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40223296349) |

The earlier [21-case alias packet](ALIAS-VALIDATION.md) covers graph limits,
cycles, alias equivalence to inline YAML and independent retained findings.
The release changes version/docs; alias rules and limits are preserved.
[Main CI](https://github.com/adi271213/workflow-privilege-check/actions/runs/40242662874)
passed on the release commit. The [tag installation](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40242719818)
resolved v0.0.1 to that commit and retained eight findings across two aliased jobs.
The [release](https://github.com/adi271213/workflow-privilege-check/releases/tag/v0.0.1)
is published on [Marketplace](https://github.com/marketplace/actions/workflow-privilege-check).

Invalid fixture files can also receive GitHub's own validation failures; listed
consumer jobs verify the analyzer's independent handling of their data. Fixtures
are never dispatched or merged. No new fork or independent human security audit
is claimed.
