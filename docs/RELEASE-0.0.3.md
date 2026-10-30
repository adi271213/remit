# 0.0.3 release checks

Evaluated runtime: `5448750967e3bc7274b213866628fc61f1769882`.
Package and module versions agree at 0.0.3.

## Completed checks

- [CI on Python 3.11–3.14](https://github.com/adi271213/workflow-privilege-check/actions/runs/41025491412):
  170 tests and six network-isolated Action controller outcomes per interpreter
  (24 isolated outcomes across the four-version CI matrix).
- [Hosted Action contract](https://github.com/adi271213/workflow-privilege-check/actions/runs/41025483978):
  24 jobs passed (12 cases in both advisory and require-complete modes), using
  the runtime pin above. Cases include WF008, unresolved associations, supported
  aliases, missing commits, errors, partial findings and Git replacement handling.
  Expected failing Action steps are asserted by the test harness; a passing
  contract job does not mean every analysis was complete.
- Wheel and source distribution versions agree. Both installed without a package
  index using the hash-verified dependency wheel. The installed CLI detected WF008;
  the source distribution rebuilt successfully and passed all 170 tests.
- The frozen 74-case historical replay verified every input hash and matched all
  45 existing labeled facts: 62 complete and 12 incomplete results. This older
  corpus contains no new WF008 findings. It is a selected regression corpus, not
  an independent accuracy study or evidence of production precision/recall.

## Fresh fork installation

The copy-ready advisory workflow was installed in a disposable public consumer.
Its calling workflow bytes matched the published template in all six cases.
PRs originated from `Adij2704`; owner `adi271213` approved each run under the
existing fork approval policy. Logs verified the exact base/head, the downloaded
runtime pin and a read-only token. Maintainer edits on the fork were disabled.
No proposed fixture was merged or dispatched.

| Case | Analysis / review | Findings | Run |
|---|---|---|---|
| Neutral change | complete / none | 0 | [41025122690](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41025122690) |
| New runner/environment association | complete / suggested | WF008 | [41025343331](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41025343331) |
| Unresolved association | incomplete / unknown | 0 | [41025580581](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41025580581) |
| Recursive alias | error / unknown | 0 | [41025663652](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41025663652) |
| Association plus dynamic secret | incomplete / suggested | WF008 | [41025896101](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41025896101) |
| Association plus invalid job | error / suggested | WF008 | [41026401359](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41026401359) |

All six advisory jobs succeeded with the expected outputs, diagnostics and
reports. The incomplete/error cases demonstrate why job success alone is not a
clean result. Require-complete behavior was tested in the hosted contract above.
These tests do not cover every repository policy or private installation.

## Scope

The release adds WF008 for configured runner/environment associations in bounded
static matrices, preserves before/after evidence, normalizes equivalent selectors
and resolves direct matrix variable names case-insensitively. These comparisons
do not prove runtime access, exploitability or PR safety. Findings remain advisory;
require-complete rejects unresolved analysis rather than enforcing approval.
