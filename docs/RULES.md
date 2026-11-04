# Rules

Each finding records the `line` in the head file that introduced it, used for
pull request annotations. Rules compare each changed workflow file between the base and head commits. Jobs
are matched by job ID; a job that exists only in the head is compared against an
empty job. Unchanged files are skipped. A file renamed without content changes is
recorded in `renames` and skipped.

A finding means a configured capability changed and someone should confirm it
was intended. It doesn't prove the job can use that capability at runtime, or
that the change is exploitable.

## WF001: token permission increase

For each job, the effective `GITHUB_TOKEN` permissions are the job's
`permissions` block, else the workflow's, else the default supplied with
`--default-permissions` / `default-permissions`. Each scope that rises in level
(`none` → `read` → `write`) is one finding. `read-all` and `write-all` are expanded
to every known scope. A new `id-token: write` is described as an OIDC token request.

Supported scopes: `actions`, `artifact-metadata`, `attestations`, `checks`,
`code-quality`, `contents`, `copilot-requests`, `deployments`, `discussions`,
`id-token`, `issues`, `models`, `packages`, `pages`, `pull-requests`,
`security-events`, `statuses`, `vulnerability-alerts`. An unknown scope or an
invalid level is an error rather than being guessed at.

When neither side declares permissions and no default is supplied, the same job
is assumed to inherit the same default on both sides, and the comparison is
listed under `inheritedComparisons`. Other comparisons involving an unknown
default are covered by WF002.

## WF002: inherited default permissions

The repository's default token permissions aren't visible to the tool. WF002
covers the changes that cross that boundary when no `default-permissions` is
supplied:

- **To the default.** A new job, or a job that used to declare permissions,
  now has no `permissions` block at job or workflow level. The default could be
  broader than before, so the finding asks for an explicit block. `before` is
  the old explicit grants (`none` if it granted nothing, empty for a new job);
  `after` is `repository default`. Switching from `write-all` is quiet, since
  nothing can exceed it.
- **From the default.** A job that used the default now declares permissions.
  The narrowest default GitHub allows is `contents: read` and `packages: read`,
  so declared levels at or below that can't be an increase and stay quiet. That
  covers the usual hardening change. Anything above it is reported as "may
  exceed the default", and the comparison is listed in `assumptions`.

Supplying `default-permissions` replaces WF002 with ordinary WF001 comparisons.

## WF003: review-sensitive trigger added

Reported when one of these event names is added to `on:`, including in a new file:

| Event | Why it deserves review |
|---|---|
| `pull_request_target` | Runs in the base repository's context for pull request activity. Check how PR code and data are handled. |
| `workflow_run` | Can have access that the triggering workflow didn't. Check artifacts and other data that cross that boundary. |
| `issue_comment` | Comments on issues and PRs can start a default-branch workflow. Check actor checks and use of comment data. |
| `issues` | Issue activity can start a default-branch workflow. |
| `discussion` | Discussion activity can start a default-branch workflow. |
| `discussion_comment` | Discussion comments can start a default-branch workflow. |

Only additions count. Removing or reordering triggers, and changes to activity
types or branch/path filters, are not reported. `pull_request` and the review
events are not in the list because GitHub restricts tokens and secrets for fork
PRs on those events. Trigger findings are independent of token permissions.

## WF004: secret reference added

For each job, the tool collects secret references from `${{ }}` expressions in
the job and in the workflow-level `env`:

- `secrets.NAME` and `secrets['NAME']` are literal references (case-insensitive);
- any other use of the whole `secrets` object, such as `toJSON(secrets)`, and
  `secrets: inherit` on a reusable-workflow call count as "all available secrets";
- `secrets[<expression>]` can't be resolved and makes the analysis `incomplete`.

Each reference present in the head but not the base is a finding. `GITHUB_TOKEN`
is ignored because WF001 covers it. If the base already used an unresolvable
selector, no addition can be established and nothing is reported for that job.
Property names keep their hyphens, so `inputs.use-secrets` is not a secrets read.

## WF005: runner selection

Reported when a job's `runs-on` changes and the new selection contains any of:

- the `self-hosted` label or a label not in the list of GitHub-hosted labels in
  [`contexts.py`](../src/privilege_check/contexts.py);
- a runner `group`;
- an expression that can't be resolved.

Labels are compared case-insensitively and without regard to order, duplicates,
or string vs. list vs. mapping form. Moves between GitHub-hosted labels (e.g.
`ubuntu-22.04` → `ubuntu-24.04`) and moves back to hosted runners are quiet. For
matrix jobs the label/group combination of each row is compared, so swapping
labels between rows is reported even when the overall label set is unchanged.

An unknown label isn't assumed to be self-hosted; it may be a larger hosted
runner. The finding asks the reviewer to confirm.

## WF007: environment change

Reported when a job's `environment` name is added, removed or changed. Names are
case-insensitive, and the string and `{name: ...}` forms are equivalent. Changing
only the `url` is quiet.

Both directions are reported because neither is always safer: adding an
environment can expose its secrets once protection rules pass, while removing one
can drop required approvals.

## WF008: runner/environment pairing

Covers the case WF005 and WF007 miss: a matrix that keeps the same set of runners
and the same set of environments but changes which runner deploys to which
environment.

```text
base: ubuntu-latest -> production; self-hosted -> staging
head: ubuntu-latest -> staging;    self-hosted -> production
```

Each matrix row's (runner labels, group, environment) tuple is compared. A pair
that exists in the head but not the base is a finding. Removing pairs is quiet,
and changes already reported by WF005 or WF007 aren't reported again. Try it
with `workflow-privilege-check scan --dirs examples/association-base examples/association-head --format markdown`.

## WF009: new third-party code in a privileged job

Reported when a job starts running an action or reusable workflow from outside the
repository (`uses: owner/repo@ref`, or `owner/repo/path@ref`) that it didn't run
before, and the job has at least one of:

- a `write` token scope or `id-token: write` (explicit, or from `default-permissions`);
- a secret reference, or all secrets via `secrets: inherit` / `toJSON(secrets)`;
- a deployment `environment`.

That code can use those privileges, so the finding lists them and asks for a
review of the action and a full-SHA pin. Changing only the ref (`@v1` → `@v2`, or
to a SHA) is quiet. Local actions (`./`), `docker://` images and actions owned by
`actions` or `github` are not reported. A job that inherits unknown default
permissions counts only its secrets and environment.

## Matrices and expressions

Expressions are never evaluated. A `runs-on`, runner group or `environment` value
of exactly `${{ matrix.<field> }}` is resolved against the job's matrix if:

- the matrix is static (no `${{ }}` anywhere in it);
- it has at most 256 rows after `exclude` and `include`, applied in GitHub's
  order (excludes first; an include entry extends every row it doesn't
  contradict, otherwise it becomes a new row);
- every row has a non-empty string for that field.

Matrix field names are case-insensitive. Hyphens are allowed
(`matrix.runner-name`). Two keys that differ only by case make the matrix
unresolvable.

Any other expression is unresolved. If an unresolved selector and its matrix are
identical on both sides, they're assumed to select the same thing and this
assumption is recorded in the report's `assumptions`. A changed unresolved
selection is reported (WF005/WF007) and makes the analysis `incomplete`.
