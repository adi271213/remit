# Install Workflow Privilege Check

Use one public repository you maintain that already runs GitHub Actions. Keep
ordinary review and existing scanners. This tool reports configured changes;
it does not approve PRs or enforce human review. Leave the job outside required
merge checks and auto-merge authorization during initial evaluation.

## Installation

Copy [the complete workflow](examples/github-action-template.yml) to
`.github/workflows/workflow-privilege-review.yml` in your repository. Its Action
step is already pinned to this evaluated source:

```text
adi271213/workflow-privilege-check@ff12d9b482a55777815dd5a1391e058986259320
```

Keep `mode: advisory`, `contents: read`, the trusted-base checkout, exact head
fetch and result-explanation step. Review the copied workflow before merging it.
The recipe uses Linux GitHub-hosted runners with Python 3.11+ and Git. It needs
no repository secrets, cloud credentials, write token, or extra account.
The verified PyYAML bundle is included; no pip/venv/download runs during analysis.
Downloading Actions and fetching public commits still require network access.
Private-repository authentication and arbitrary self-hosted installations are not
covered by this setup recipe. Do not broaden permissions to force installation.

The calling workflow remains editable in PRs. Pinning the scanner does not make
that calling workflow an unbypassable boundary. Normal fork approval rules apply.
The 0.0.4 [release checks](docs/RELEASE-0.0.4.md) record the current setup and
pinned runtime installation tests, including fresh fork PRs. Fork tests cover advisory mode,
including approval before execution and incomplete/error outcomes; they do not
validate every repository policy or private-repository installation.

## Two onboarding checks

After installation reaches the default branch:

1. Open a README-only PR. Expect `complete / none / 0 findings` and analysis exit 0.
2. In a separate PR add the unused workflow below as
   `.github/workflows/pilot-read-grant.yml`. Expect `complete / suggested`, one
   WF001 finding and analysis exit 0. Do not dispatch or merge this fixture;
   inspect the summary and close the PR.

```yaml
name: Pilot read-grant fixture
on: workflow_dispatch
permissions: {}
jobs:
  fixture:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - run: echo "Manual pilot fixture"
```

Record both run URLs. If results differ, inspect the diagnostic and report the
public PR/run links. Never invent token defaults or add write access for the test.

## Interpret the outputs

| Analysis / review | Meaning |
|---|---|
| complete / none | No supported configured change was found; continue ordinary review |
| complete / suggested | Inspect the intended token/trigger/secret/context changes |
| incomplete / unknown | Missing context; zero findings is not a clean result |
| incomplete or error / suggested | Inspect known findings and unresolved parts |
| error / unknown | Input or analysis failed; inspect the diagnostic |
| failed step / missing outputs | Execution or report publication did not finish |

Advisory mode can succeed with incomplete/error analysis. Default
`require-complete` fails those states, but **neither mode fails just because
findings exist**. A required status alone does not require approval of grants.
[README](README.md#outcomes) separates these outcomes from CLI exits.

Outputs are `analysis-status`, `review-status`, `finding-count`,
`analysis-exit-code`, `report-path`, `summary-path`, `base-sha` and `head-sha`.
JSON/Markdown reports stay in the GitHub job logs/summary and job-local files;
no PR comments, telemetry or external reporting service are used.

## Troubleshooting

If the fetch step says the PR head does not match the event, the PR may have
changed while the run was starting. Run the workflow for the latest PR revision
again after GitHub updates the pull ref. Keep the equality check: analyzing a
different head would give a report for the wrong revision.

If fetching fails, inspect the fetch error and repository visibility. This recipe
fetches public commits without stored checkout credentials. For an analysis
`incomplete` or `error`, inspect the summary rather than treating a successful
advisory step as a clean result. Report ordinary bugs with a small public or
synthetic reproduction; use [private reporting](SECURITY.md) for vulnerabilities.

## Coverage and feedback

See [validation](VALIDATION.md), [trigger policy](docs/TRIGGER-POLICY.md),
[runner/environment policy](docs/CONTEXT-POLICY.md) and [YAML policy](docs/YAML-POLICY.md).
The installation pin above contains the 0.0.4 runtime, including bounded YAML
alias support and runner/environment association findings.
See [known release limitations](docs/KNOWN-LIMITATIONS.md) when reviewing older installations.
For the optional advisory trial, see [PILOT.md](PILOT.md). No production
precision/recall or independent human security audit is claimed.
