# Workflow Privilege Check

[![CI](https://github.com/adi271213/workflow-privilege-check/actions/workflows/ci.yml/badge.svg)](https://github.com/adi271213/workflow-privilege-check/actions/workflows/ci.yml)

A GitHub Action and CLI that compares the GitHub Actions workflows at a pull
request's base and head commits and reports changes that give workflows more
privilege: wider `GITHUB_TOKEN` scopes, sensitive new triggers, new secret
references, self-hosted or custom runners, and deployment environment changes.

Workflow files are read as data. Nothing from the pull request is executed and
the analysis makes no network calls.

## Why

Security-relevant workflow edits are often one line in a large diff:
`contents: read` becomes `write`, a `pull_request_target` trigger appears, a
reusable-workflow call gains `secrets: inherit`, or a release job starts running
a new third-party action. This tool answers one question: **what did this PR
change about what the workflows are allowed to do?** Configuration that didn't
change produces no output, so the report contains only the difference.

### Use it alongside zizmor

[zizmor](https://github.com/zizmorcore/zizmor) audits the current state of a
workflow for risky patterns, and with GitHub code scanning a PR shows the alerts
it introduced. Many privilege increases never become a new alert, because the
result isn't "bad" by a state rule: a job gaining `id-token: write`, a new
secret reference, a changed environment, or a new action receiving write access.

On the [74 historical PRs](benchmarks/README.md), this tool reported 69 findings.
For 43 of them (62%), zizmor 1.32 (pedantic, offline) reported no new finding of
a related audit in the same workflow and job; for new secret references, none of
8. Reproduce with `scripts/compare_zizmor.py`. Run zizmor for what is dangerous,
and this for what got wider.

## Example

Adding a `pull_request_target` trigger, OIDC and package write access, and a
new secret to a release workflow produces this
([full sample](examples/sample-report.md)):

| Rule | Before | After | Change |
|---|---|---|---|
| WF003 | Not recorded | pull_request_target | Review-sensitive trigger pull_request_target introduced. |
| WF001 | id-token: none; packages: none | id-token: write; packages: write | Job publish gains 2 higher token permission scopes, including an OIDC identity token. |
| WF004 | Not recorded | PUBLISH_TOKEN | Job publish adds a reference or forwarding path to PUBLISH_TOKEN. |

In a pull request, each finding also appears as an annotation on the line that
introduced it, in the **Files changed** tab. The job summary groups findings by
workflow and job, with a short question for the reviewer. The JSON report
([sample](examples/sample-report.json)) has the same data for tooling.

## Rules

| Rule | Reports |
|---|---|
| WF001 | A job's token scope increases (`none` → `read` → `write`), including new `id-token: write` (OIDC) |
| WF002 | A job starts relying on the repository's default token permissions, or replaces them with permissions that may exceed the default |
| WF003 | A newly added `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion` or `discussion_comment` trigger |
| WF004 | A job newly references a secret, or forwards all secrets (`secrets: inherit`, `toJSON(secrets)`) |
| WF005 | A job's runner changes to a self-hosted, custom-label, runner-group or unresolvable selection |
| WF007 | A job's deployment environment is added, removed or changed |
| WF008 | A matrix job pairs a runner with a different environment while the overall runner and environment sets stay the same |
| WF009 | Third-party code (an action or reusable workflow) newly runs in a job with write scopes, OIDC, secrets or an environment |

See [docs/RULES.md](docs/RULES.md) for the exact behaviour of each rule.

## Quick start

Copy the 45-line [`examples/github-action-template.yml`](examples/github-action-template.yml)
into `.github/workflows/` and merge it. The template checks out the base commit,
fetches the PR head without checking it out, and runs the Action pinned to a
full commit SHA:

```yaml
- uses: adi271213/workflow-privilege-check@ff12d9b482a55777815dd5a1391e058986259320 # v0.0.4
  with:
    mode: advisory
```

The step needs both commits in the local clone, so use the full template rather
than this step on its own. [SETUP.md](SETUP.md) covers inputs, outputs and
troubleshooting.

## Results

Every run produces an **analysis** status and a **review** status:

| Analysis | Meaning | CLI exit | `require-complete` (default) | `advisory` |
|---|---|---|---|---|
| `complete` | All changed workflows were compared | 0 | pass | pass |
| `incomplete` | Some context is unknown, e.g. a dynamic expression | 2 | fail | pass with warning |
| `error` | Some input couldn't be parsed or read | 2 | fail | pass with warning |

Review is `suggested` when there are findings, `none` when analysis is complete
with no findings, and (in the Action) `unknown` when analysis is not complete and
nothing was found. Known findings are still reported alongside incomplete or
failed parts.

**Findings never fail the step.** This is a review aid, not a merge gate: a
clean report does not mean a PR is safe, and a PR can edit the workflow that
runs the check.

### Inherited token permissions

A job without a `permissions` block gets the repository or organization default,
which this tool can't see. When a PR adds such a job, or removes a job's
`permissions` block, WF002 asks the author to declare permissions explicitly.
When a job that used the default starts declaring permissions, only levels above
GitHub's narrowest possible default (`contents: read`, `packages: read`) are
reported, so ordinary hardening PRs stay quiet. To compare against your real
default instead, pass it in:

```yaml
  with:
    default-permissions: '{"contents": "read"}'
```

## Limitations

- Only top-level `.github/workflows/*.yml` and `*.yaml` files are read. Called
  reusable workflows, actions and scripts are not followed.
- Repository and organization settings are not visible: default token
  permissions, runner inventory, environment protection rules and secrets.
- WF003 looks at trigger names only. Filter changes on existing triggers
  (branches, types, paths) are not analysed.
- Expressions are not evaluated. Only direct `${{ matrix.<field> }}` references
  into a static matrix of up to 256 rows are resolved; anything else is reported
  as unresolved.
- YAML merge keys (`<<`) and recursive aliases are rejected as errors.
- A renamed file is matched only if its content is identical; an edited rename
  is treated as a new file and can produce findings for unchanged settings.
- Input limits: 200 workflow files and 4 MiB per commit, 256 KiB per file.

## Command line

```sh
pip install workflow-privilege-check   # or, from a clone: pip install -e .
workflow-privilege-check scan --dirs examples/base examples/head --format markdown
workflow-privilege-check scan --repo /path/to/repo --base main --head my-branch
```

Output is JSON by default. `--output FILE` writes the report to a file and
`--summary FILE` appends the Markdown summary. The exit code is 0 for complete
analysis and 2 otherwise.

## Status

Early (0.x): the JSON format and rule set may still change. Each release is tested with the unit and integration
suite on Python 3.11–3.14, an end-to-end run of the Action with networking
disabled, and a replay of [74 historical public PRs](benchmarks/README.md). The
replay's expected results were labelled by the project, so treat it as a
regression suite rather than an accuracy measurement.

[Setup](SETUP.md) · [Rules](docs/RULES.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) ·
[MIT license](LICENSE)
