# Workflow Privilege Check

[![CI](https://github.com/adi271213/workflow-privilege-check/actions/workflows/ci.yml/badge.svg)](https://github.com/adi271213/workflow-privilege-check/actions/workflows/ci.yml)

An experimental, free, MIT-licensed review aid for GitHub
Actions configuration changes between a PR's exact base and head commits.
It reports selected token, trigger, secret-reference, runner and environment
changes for a human to inspect. Intended changes are reported too.

This complements [zizmor](https://github.com/zizmorcore/zizmor) and ordinary review.
It does not establish PR safety, catch arbitrary malicious code, or authorize
auto-merge. Keep it outside required merge checks during the advisory pilot.

For example, changing a job from `permissions: {contents: read}` to
`permissions: {contents: write}` produces a WF001 finding for that job. An
unchanged declaration stays quiet. The Markdown report groups findings by workflow
and job, shows the recorded before/after values, and gives reviewer questions for
each rule. Long values are shortened with a notice; JSON keeps the full evidence.
See a [sample report](examples/sample-report.md).

## Install

Use the [complete setup guide](SETUP.md) and
[copy-ready workflow](examples/github-action-template.yml). The workflow checks
out the trusted base and fetches the head as Git data. The Action is pinned to
the evaluated full commit, not loaded from the proposed checkout.

```yaml
- uses: adi271213/workflow-privilege-check@ff12d9b482a55777815dd5a1391e058986259320 # v0.0.4
  with:
    mode: advisory
```

This step requires both Git commits locally; use the full template for checkout
and fetch setup. A release tag is convenient but mutable; the full SHA is the
recommended installation. The Action needs Python 3.11+ and Git on a Linux runner.
Its hash-verified pure-Python PyYAML bundle requires no runtime pip, venv or
dependency download. Downloading the Action and fetching commits can require
network access. See [dependency provenance](vendor/README.md).

## Outcomes

Findings never fail the Action by themselves. Making this job a required check
will **not** require approval of reported grants. This is an advisory tool.

| Analysis | Review output | CLI exit | `require-complete` Action (default) | `advisory` Action |
|---|---|---|---|---|
| complete, no findings | none | 0 | success | success |
| complete, findings | suggested | 0 | success | success |
| incomplete/error, no known findings | unknown | 2 | failure | success with warning |
| incomplete/error, known findings | suggested | 2 | failure | success with warning |

The CLI JSON's `review` field is `none` or `suggested`; the Action additionally
exports `unknown` for unresolved analysis without findings. Missing reports,
publication failures and invalid modes fail the Action. A successful step or
zero findings is not evidence that a PR is safe.
JSON `schemaVersion` identifies the report format independently of the package version.

## Coverage

| Rule | Configured change reported |
|---|---|
| WF001 | Per-job token scope increases, including read increases and OIDC requests |
| WF003 | New selected review-sensitive trigger names; [policy](docs/TRIGGER-POLICY.md) |
| WF004 | New per-job literal secret references, workflow-env references or whole-secret forwarding |
| WF005 | Changed/new self-hosted, custom/group or unresolved runner selections |
| WF007 | Added, removed or changed environment targets |
| WF008 | New runner/environment pairings when both individual target sets stay unchanged |

The [association example](docs/ASSOCIATION-ANALYSIS.md) shows a change that swaps
production onto a self-hosted runner while preserving both individual sets.
Version 0.0.4 includes WF008 and the before/after report, with corrected expression identifier handling.

[Runner/environment policy](docs/CONTEXT-POLICY.md) explains normalization, bounded
static matrix resolution, symbolic assumptions and uncertainty. Standard hosted
OS/version updates stay quiet. A runner/environment context finding is not proof
of expanded runtime authority. Environment changes can add approval constraints
as well as secret access.

Only immediate `.github/workflows/*.yml` and `*.yaml` files are read. Analysis
executes no proposed code and performs no network calls. It does not inspect
scripts, action/reusable-workflow bodies, cloud trust policies, existing-trigger
filters, actual runner inventory, or environment secrets/protection settings.
YAML anchors/aliases are supported within explicit graph limits; recursive aliases,
over-budget expansion and YAML merge keys produce an explicit error. See
[alias policy](docs/YAML-POLICY.md).
Source limits are 200 files / 4 MiB per snapshot, 256 KiB per file, and bounded
YAML depth/tokens. Exact-content file renames are recognized; edited renames and
new job IDs can conservatively produce addition findings.

## Local use and validation

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
workflow-privilege-check scan --dirs examples/base examples/head --format markdown
workflow-privilege-check scan --repo /path/to/repo --base BASE_SHA --head HEAD_SHA
python scripts/validate.py
```

Unknown inherited/explicit token transitions remain incomplete. Supply a trusted
operator assertion with `--default-permissions '{"contents":"read"}'` when known;
the tool does not guess repository defaults. Unchanged inherited values for
matched job IDs compare symbolically under a disclosed fixed-default assumption.

CI covers Python 3.11–3.14 and exercises the Action in a disconnected network
namespace. [Release checks](docs/RELEASE-0.0.4.md) and [validation method](VALIDATION.md) separate synthetic tests, hosted
installation checks and the [74-PR historical regression replay](benchmarks/README.md).
The replay is selected and self-labeled; it is not production precision/recall.
Maintainer usefulness and independent human security validation remain unproven.

[Contributing](CONTRIBUTING.md) · [Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [MIT license](LICENSE)
