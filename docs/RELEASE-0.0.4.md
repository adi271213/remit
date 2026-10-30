# 0.0.4 release checks

Evaluated runtime: `ff12d9b482a55777815dd5a1391e058986259320`.
Package and module versions agree at 0.0.4.

## Correctness changes

The identifier regressions fail against 0.0.3 and pass with this patch. A
hyphenated input property no longer creates false whole-secret access or hides
a new literal reference. Hyphenated direct matrix fields resolve without
expression evaluation, including runner/environment association comparisons.
Known findings remain visible alongside unresolved or invalid input.

## Completed checks

- [Python 3.11–3.14 CI](https://github.com/adi271213/workflow-privilege-check/actions/runs/41096798690):
  177 tests and 12 network-isolated controller outcomes per interpreter
  (48 isolated outcomes across the four-version matrix).
- [Hosted Action contract](https://github.com/adi271213/workflow-privilege-check/actions/runs/41096795345):
  32 jobs passed, covering 16 fixtures in both modes. This includes the missed
  secret reproduction, a quiet hyphenated input, a full-name prefix regression,
  static associations, partial findings, errors and Git replacement/redirection.
  Expected failing Action steps are asserted by successful contract jobs.
- The contract now builds its Git objects from checked-in
  `tests/hosted_cases.json` using `scripts/hosted_fixture.py`. It no longer
  depends on the disposable pilot repository. Those cases also run locally
  through the actual isolated controller in the ordinary test suite.
- Wheel/source versions agree. Offline installation, source rebuild, the installed
  CLI's association example and the full 177-test extracted-source suite pass.
  The final package check also verifies the previously missed DEPLOY_KEY reference
  through the installed CLI, without importing the source checkout.
- The frozen 74-PR replay verifies every input hash and matches all 45 legacy
  facts: 62 complete and 12 incomplete reports. It has no WF008 positives. This
  selected, self-labeled regression packet is not independent accuracy evidence.

## Fresh fork installation

The copy-ready advisory workflow was installed in a disposable public consumer.
A fresh PR from `Adij2704` exercised seven revisions. Owner `adi271213` approved
runs under the existing fork policy after checking the caller and input bytes.
Logs verify the exact runtime pin, base/head, read-only token and expected outputs.
The calling workflow matches the public template; maintainer edits were disabled.
No proposed fixture was merged or dispatched.

| Case | Analysis / review | Findings | Evidence |
|---|---|---|---|
| neutral | complete / none | 0 | [run 41097172046](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097172046) |
| hyphen-secret | complete / suggested | WF004 | [run 41097307367](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097307367) |
| hyphen-association | complete / suggested | WF008 | [run 41097410741](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097410741) |
| incomplete-unknown | incomplete / unknown | 0 | [run 41097541148](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097541148) |
| error-unknown | error / unknown | 0 | [run 41097628069](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097628069) |
| incomplete-known | incomplete / suggested | WF008, WF004 | [run 41097762146](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097762146) |
| error-known | error / suggested | WF008, WF004 | [run 41097881468](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/41097881468) |

All seven advisory jobs succeeded with the expected reports. Incomplete/error
success is not a clean analysis: unknown outcomes stay explicit and established
WF004/WF008 findings survive the remaining uncertainty. The hosted contract
separately validates require-complete failures for unresolved cases.

## Evidence correction and boundary

The 0.0.3 release evidence previously overstated its isolated count per Python
version. It ran six per interpreter (24 across four versions), while its separate
hosted contract had 24 jobs. The current main documentation and editable release
notes correct that wording; protected historical tags are not rewritten.

These checks establish bounded synthetic correctness and a public advisory
installation path. They do not establish private-repository support, effective
runtime access, exploitability, production precision/recall, independent human
security validation or external maintainer usefulness. Findings remain advisory;
keep the initial installation outside required merge checks.
