<div align="center">

# Remit

**Know when a pull request widens your workflows' authority.**

[![CI](https://github.com/adi271213/remit/actions/workflows/ci.yml/badge.svg)](https://github.com/adi271213/remit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/remit-actions)](https://pypi.org/project/remit-actions/)
[![Python](https://img.shields.io/pypi/pyversions/remit-actions)](https://pypi.org/project/remit-actions/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/adi271213/remit/blob/main/LICENSE)

</div>

The changes that matter in a workflow PR are often a single line: `contents: read`
becomes `write`, a `pull_request_target` trigger appears, a release job starts
running a new third-party action with your secrets. Remit compares the base and
head of every pull request and puts each of those changes on the line that
introduced it, so reviewers can't miss them.

- **Only what changed.** Unchanged configuration stays quiet, so ordinary PRs get no noise.
- **Flags common pwn-request patterns.** Privileged workflows that start checking out, fetching or downloading pull request content, including the time-of-check to time-of-use trap after a label or comment approval.
- **Right on the diff.** Findings appear as annotations in the PR's *Files changed* tab.
- **Safe on untrusted PRs.** The PR is read as data and never executed; the analysis makes no network calls.
- **Nothing to install.** A pinned Action with a hash-verified bundled parser; no secrets, `contents: read` only.

## What it catches

A PR edits a release workflow:

```diff
 name: Release
-on: push
+on: [push, pull_request_target]
 permissions: {}
 jobs:
   publish:
     runs-on: ubuntu-latest
     permissions:
-      contents: read
+      contents: write
+      id-token: write
     steps:
       - uses: actions/checkout@v4
       - run: make dist
+      - uses: someone/release-action@v1
+        with:
+          token: ${{ secrets.RELEASE_TOKEN }}
```

Remit annotates five lines of that diff:

| Line | Rule | Finding |
|---|---|---|
| 2 | WF003 | Review-sensitive trigger `pull_request_target` introduced. |
| 8 | WF001 | Job publish is newly configured to use `contents: write`. |
| 9 | WF001 | Job publish is newly configured to request an OIDC identity token. |
| 13 | WF009 | Job publish now runs third-party code from `someone/release-action@v1`, which can use `contents: write`; `id-token: write`; secrets: `RELEASE_TOKEN`. |
| 15 | WF004 | Job publish adds a reference or forwarding path to `RELEASE_TOKEN`. |

The job summary groups the same findings by workflow and job, with a question
for the reviewer on each ([sample](https://github.com/adi271213/remit/blob/main/examples/sample-report.md)).
JSON and SARIF reports carry the same data for tooling and GitHub code scanning.

## Quick start

1. Copy [`examples/github-action-template.yml`](https://github.com/adi271213/remit/blob/main/examples/github-action-template.yml)
   (45 lines) to `.github/workflows/remit.yml`.
2. Merge it.
3. Open a pull request that touches a workflow and look at *Files changed*.

The template checks out the base commit, fetches the PR head without checking it
out, and runs the Action pinned to a full commit SHA:

```yaml
- uses: adi271213/remit@3db5c481c527a7f60bf92c0499083fe15f7829be # v1
  with:
    mode: advisory
```

Use the whole template rather than this step alone: the step needs both commits
in the local clone. The [setup guide](https://github.com/adi271213/remit/blob/main/SETUP.md)
covers inputs, outputs, code scanning and troubleshooting.

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
| WF010 | A `pull_request_target`, `workflow_run` or `issue_comment` job newly checks out, fetches or downloads pull request content: the "pwn request" |
| WF011 | An approval-gated privileged job checks out a pull request reference that can change after approval: time-of-check to time-of-use |

Rules follow steps into local composite actions and local reusable workflows
(`./` and `$/` references), so a change inside `.github/actions/` is caught even
when no workflow file changed.

[docs/RULES.md](https://github.com/adi271213/remit/blob/main/docs/RULES.md) describes the exact behaviour of each rule.

## Remit and zizmor

[zizmor](https://github.com/zizmorcore/zizmor) audits what your workflows *are*
for risky patterns. Remit reports what a pull request *changed*, including
increases that never become a zizmor alert because the end state isn't "bad"
by a state rule: a job gaining `id-token: write`, a new secret reference, a
changed environment, or a new action receiving write access.

On [74 historical public PRs](https://github.com/adi271213/remit/blob/main/benchmarks/README.md),
Remit reported 72 findings. For 46 of them (64%), zizmor 1.32 (pedantic,
offline) reported no new finding of a related audit in the same workflow and
job, including all 8 new secret references. The PRs were selected and labelled
by this project and the matching is approximate, so read this as an indication,
not a benchmark. Run zizmor for what is dangerous, and Remit for what got wider.

## Results

Every run reports an **analysis** status and a **review** status:

| Analysis | Meaning | CLI exit | `require-complete` (default) | `advisory` |
|---|---|---|---|---|
| `complete` | All changed workflows were compared | 0 | pass | pass |
| `incomplete` | Some context is unknown, e.g. a dynamic expression | 2 | fail | pass with warning |
| `error` | Some input couldn't be parsed or read | 2 | fail | pass with warning |

Review is `suggested` when there are findings, `none` when analysis is complete
with no findings, and (in the Action) `unknown` when analysis is incomplete and
nothing was found. Known findings are reported alongside incomplete or failed parts.

**Findings never fail the step.** Remit is a review aid, not a merge gate: a
clean report doesn't mean a PR is safe, and a PR can edit the workflow that runs
the check.

<details>
<summary><b>Inherited token permissions</b></summary>

A job without a `permissions` block gets the repository or organization default,
which Remit can't see. When a PR adds such a job, or removes a job's
`permissions` block, WF002 asks the author to declare permissions explicitly.
When a job that used the default starts declaring permissions, only levels above
GitHub's narrowest possible default (`contents: read`, `packages: read`) are
reported, so ordinary hardening PRs stay quiet. To compare against your real
default instead, pass it in:

```yaml
  with:
    default-permissions: '{"contents": "read"}'
```

</details>

<details>
<summary><b>Limitations</b></summary>

- Workflows are read from `.github/workflows/`, and local composite actions and
  reusable workflows are followed. Actions and reusable workflows from other
  repositories, and the contents of scripts, are not analysed.
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
- Input limits: 200 workflow files and 4 MiB per commit; per file, 256 KiB and
  60,000 YAML tokens (a very dense file can reach the token limit first).
- WF010 and WF011 follow pull request references through environment variables,
  `$GITHUB_ENV`, step and job outputs, and action inputs within the repository.
  Values computed in other ways (a script that builds a ref from pieces, files
  passed between jobs) are not traced.

</details>

## Command line

The package is `remit-actions` on PyPI; the command it installs is `remit`.

```sh
pip install remit-actions
remit scan --repo . --base main --head my-branch --format markdown
remit scan --dirs path/to/before path/to/after --format sarif --output remit.sarif
```

Output is JSON by default; `--format markdown` and `--format sarif` are also
available. `--summary FILE` appends the Markdown summary and `--sarif FILE`
also writes SARIF. The exit code is 0 for complete analysis and 2 otherwise.

## Audit an existing repository

Pull request checks only see what a PR changes. `remit audit` reports what is
already there: every place a `pull_request_target`, `workflow_run` or
`issue_comment` job brings in pull request content (WF010), and every mutable
checkout after a label, comment or environment approval (WF011), including
through local actions and reusable workflows.

```sh
remit audit --repo .                          # the current commit
remit audit --repo . --ref v2.3.0             # any commit or tag
remit audit --dir path/to/checkout --format markdown
remit audit --repo . --format sarif --output remit-audit.sarif
```

Like `scan`, it reads committed Git objects (or a directory) as data and runs
nothing. The exit code is 0 for a complete audit, 2 when something couldn't be
analysed, and with `--fail-on-findings`, 1 when the audit found something. The
[setup guide](https://github.com/adi271213/remit/blob/main/SETUP.md#scheduled-audit)
has a weekly scheduled audit workflow.

## Status

Rule IDs, Action inputs and outputs, and the JSON report format stay compatible
within a version; an incompatible change gets a new version number. Each release
runs the test suite on Python 3.11–3.14, runs the Action end to end with networking
disabled, and replays 74 historical public PRs. The replay's expected results
were labelled by the project, so treat it as a regression suite rather than an
accuracy measurement. Feedback from real repositories is the most useful thing
you can send: open a [trial feedback issue](https://github.com/adi271213/remit/issues/new?template=trial_feedback.md).

[Setup](https://github.com/adi271213/remit/blob/main/SETUP.md) ·
[Rules](https://github.com/adi271213/remit/blob/main/docs/RULES.md) ·
[Architecture](https://github.com/adi271213/remit/blob/main/docs/ARCHITECTURE.md) ·
[Contributing](https://github.com/adi271213/remit/blob/main/CONTRIBUTING.md) ·
[Security](https://github.com/adi271213/remit/blob/main/SECURITY.md) ·
[Changelog](https://github.com/adi271213/remit/blob/main/CHANGELOG.md) ·
[MIT license](https://github.com/adi271213/remit/blob/main/LICENSE)
