# Setup

## Requirements

- A Linux GitHub-hosted runner. `ubuntu-latest` already has Python 3.11+ and Git.
- A public repository. The template fetches the PR head without stored
  credentials; private repositories need an authenticated fetch, which the
  template doesn't cover.
- No secrets and no write permissions. The job runs with `contents: read`.

The Action ships a hash-verified copy of PyYAML (see [vendor/](vendor/README.md)),
so nothing is installed with pip at runtime.

## Install

1. Copy [`examples/github-action-template.yml`](examples/github-action-template.yml)
   to `.github/workflows/remit.yml`.
2. Review it and merge it through your normal process.
3. Make sure a person who knows your CI reviews workflow changes. Remit points at
   privilege changes but never blocks a merge, so the review is what acts on
   them. A `CODEOWNERS` file with branch protection's "Require review from Code
   Owners" does this:

   ```text
   /.github/  @your-org/ci-owners
   ```

The template:

1. checks out the PR's **base** commit with `persist-credentials: false`;
2. fetches the PR **head** as Git objects without checking it out, and stops if
   the fetched commit doesn't match the event's head SHA;
3. runs the Action, pinned to a full commit SHA, in `advisory` mode.

Findings appear as annotations in the PR's **Files changed** tab (up to 10 per
run) and in full in the job summary. When there are more, an incomplete analysis
is announced first, pull request content in privileged jobs (WF010, WF011) comes
next, and a job's token scope increases share one annotation.

Pin the Action to a full commit SHA. Tags are convenient but can be moved.

Keep the job out of required status checks while you evaluate it. Findings never
fail the step, so making it required would not force anyone to review them.

## Check the installation

After the workflow is on your default branch:

1. Open a PR that only edits the README. Expect `complete / none`, 0 findings.
   (This repository runs the same check on itself; see
   [`privilege-review.yml`](.github/workflows/privilege-review.yml).)
2. Open a separate PR that adds this file as
   `.github/workflows/pilot-read-grant.yml`. Expect `complete / suggested` with
   one WF001 finding. Close the PR afterwards without merging.

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

## Inputs

| Input | Default | Description |
|---|---|---|
| `mode` | `require-complete` | `require-complete` fails the step when analysis is incomplete or errored. `advisory` never fails because of the analysis result. |
| `base` | merge-base of the PR | Base commit SHA (full 40 or 64 hex characters). By default the Action compares from where the PR branched off, like GitHub's *Files changed*, so changes merged to the base branch since then don't show up reversed. |
| `head` | PR head SHA | Head commit SHA. |
| `repository-path` | `.` | Local clone that contains both commits. |
| `default-permissions` | — | JSON map of your repository's default token permissions, e.g. `{"contents":"read"}`. Lets jobs without a `permissions` block be compared. Set this in the calling workflow, never from PR content. |

## Outputs

| Output | Values |
|---|---|
| `analysis-status` | `complete`, `incomplete` or `error` |
| `review-status` | `suggested`, `none` or `unknown` |
| `finding-count` | Number of findings |
| `analysis-exit-code` | `0` if complete, otherwise `2` (independent of `mode`) |
| `report-path` | JSON report in `$RUNNER_TEMP` |
| `summary-path` | Markdown summary in `$RUNNER_TEMP` |
| `base-sha`, `head-sha` | Resolved commits; empty if they couldn't be resolved |
| `sarif-path` | SARIF 2.1.0 report in `$RUNNER_TEMP`; empty if the analysis didn't run |

The Markdown summary is also written to the job summary. The Action posts no PR
comments and sends nothing to external services.

## Scheduled audit

To check what is already in the repository, not only what pull requests change,
run `remit audit` on a schedule. It reports WF010 and WF011 in the current
workflows and local actions:

```yaml
name: Remit audit
on:
  schedule:
    - cron: "17 6 * * 1"   # weekly
  workflow_dispatch:
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: '3.13'
      - run: pip install remit-actions==1
      - run: remit audit --repo . --format markdown --summary "$GITHUB_STEP_SUMMARY" --fail-on-findings
```

The job fails when the audit finds something, and the findings are in the job
summary. Add `--sarif remit-audit.sarif` and an upload step (see below) to keep
them in the Security tab; audit results use their own code scanning category, so
they don't interfere with pull request results.

## Code scanning (optional)

If your repository uses GitHub code scanning, you can also send findings to the
**Security** tab. Give the step an `id`, add `security-events: write` to the
job's permissions, and add:

```yaml
      - name: Upload to code scanning
        if: always() && steps.privilege.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@1fc58d04a4d4374f921bdac573c3811c240f9c26 # v4.39.2
        with:
          sarif_file: ${{ steps.privilege.outputs.sarif-path }}
          category: remit
```

Pull requests from forks get a read-only token, so the upload step fails for
them; the annotations and job summary still work. Each alert carries a stable
fingerprint, so moving a line doesn't create a new alert. The CLI writes the
same format with `--format sarif` or `--sarif FILE`.

## Reading the result

| Analysis / review | What to do |
|---|---|
| `complete / none` | Nothing in scope changed. Continue normal review. |
| `complete / suggested` | Check that each reported change is intended. |
| `incomplete / unknown` | Some context is missing; zero findings is not a clean result. Read the diagnostics. |
| `incomplete` or `error` / `suggested` | Check the findings and the unresolved parts. |
| `error / unknown` | Input couldn't be read or parsed. Read the diagnostics. |
| Failed step or missing outputs | The Action itself didn't finish. |

## Troubleshooting

**"The fetched PR head does not match this event."** The PR was updated while
the run was starting. Re-run the workflow for the latest commit. Don't remove the
check: without it the report could describe a different commit.

**Fetch fails.** Check the error and the repository's visibility. The template
fetches without credentials, so this is expected for private repositories.

**WF002 on every new job.** Add a `permissions` block to the workflow or job.
This is good practice anyway: it limits what the job's token can do.

**WF002 "may exceed that default".** A job that used the repository default now
declares something above `contents: read` / `packages: read`. Whether that's an
increase depends on your repository setting; set `default-permissions` to get
an exact comparison.

Report bugs with a small public or synthetic reproduction. Report
vulnerabilities privately; see [SECURITY.md](SECURITY.md).
