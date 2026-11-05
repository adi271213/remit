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

A new job's `read` scopes are not reported: they are narrower than any default
token, so declaring them is hardening, not an increase. Its `write` scopes and
`id-token: write` are reported, and so is a `read` scope added to an existing job.

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
  broader than before, so the finding asks for an explicit block. A new job in a
  workflow whose jobs already ran with the default changes nothing and is quiet;
  the first such job in a workflow, or a new workflow, is reported. `before` is
  the old explicit grants (`none` if it granted nothing, empty for a new job);
  `after` is `repository default`. Switching from `write-all` is quiet, since
  nothing can exceed it.
- **From the default.** A job that used the default now declares permissions.
  Declaring read access is hardening, so only `write` scopes above the
  narrowest default GitHub allows (`contents: read`, `packages: read`) are
  reported, as "may exceed the default", and the comparison is listed in
  `assumptions`.

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
  [`contexts.py`](../src/remit/contexts.py);
- a runner `group`;
- an expression that can't be resolved.

Labels are compared case-insensitively and without regard to order, duplicates,
or string vs. list vs. mapping form. Moves between GitHub-hosted labels (e.g.
`ubuntu-22.04` → `ubuntu-24.04`) and moves back to hosted runners are quiet. For
matrix jobs the label/group combination of each row is compared, so swapping
labels between rows is reported even when the overall label set is unchanged.

An unknown label isn't assumed to be self-hosted; it may be a larger hosted
runner. The finding asks the reviewer to confirm.

A change from a selection that couldn't be resolved (an expression) to
GitHub-hosted labels only is quiet and complete: whatever ran before, nothing
self-hosted or custom is introduced.

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
with `remit scan --dirs examples/association-base examples/association-head --format markdown`.

## WF009: new third-party code in a privileged job

Reported when a job starts running an action or reusable workflow from outside the
repository (`uses: owner/repo@ref`, or `owner/repo/path@ref`) that it didn't run
before, and the job has at least one of:

- a `write` token scope or `id-token: write` (explicit, or from `default-permissions`);
- a secret reference, or all secrets via `secrets: inherit` / `toJSON(secrets)`;
- a deployment `environment`.

That code can use those privileges, so the finding lists them and asks for a
review of the action and a full-SHA pin. Changing only the ref (`@v1` → `@v2`, or
to a SHA) is quiet. `docker://` images and actions owned by `actions` or `github`
are not reported. Third-party code reached through a local composite action or a
local reusable workflow counts too, and the finding is placed on that file's
`uses:` line (see [Local code](#local-code)). A job that inherits unknown default
permissions counts only its secrets and environment.

A reference to the repository itself by full name
(`owner/repo/.github/workflows/build.yml@main`) is its own code, not third-party
code, when the repository name is known: the Action passes it, and the CLI takes
`--repository-name owner/repo`. A self-reference by full commit SHA is still
reported, because GitHub also resolves SHAs of commits that exist only in a fork.

When one change in a shared local action or reusable workflow reaches several
jobs, it is reported once, with every job listed in `jobs`.

## WF010: pull request content in a privileged workflow

The "pwn request". Workflows triggered by `pull_request_target`, `workflow_run`
or `issue_comment` run with the base repository's secrets and, by default, a
token that can write. They are safe only while they don't run anything the pull
request author controls. WF010 is reported when such a job newly:

- checks out the pull request (`actions/checkout` with a `ref` or `repository`
  taken from `github.event.pull_request.head.*`, `github.head_ref`,
  `github.event.workflow_run.head_*` or `refs/pull/…`);
- fetches it in a script: `gh pr checkout`, `git fetch … pull/…`,
  `gh pr diff … | git apply` (or `git am`, `patch`), or a `git checkout`,
  `switch`, `reset`, `fetch`, `clone` or `gh repo clone` command naming one of
  those expressions on the same line;
- downloads an archive or patch of it (`curl` or `wget` naming a pull request
  expression, fetching a tarball, zipball, `/archive/`, `.diff` or `.patch`, or
  piping into `tar`, `unzip`, `git apply`, `patch` or a shell). A download of pull
  request metadata, such as its labels, is not content and stays quiet;
- downloads artifacts from the triggering run (`actions/download-artifact` with a
  `workflow_run` run ID, `dawidd6/action-download-artifact`, `gh run download`
  with a `workflow_run` run ID, or `downloadArtifact` in an `actions/github-script`
  script that refers to `workflow_run`).

The finding lists the trigger and what the job can use. It is also reported when
an existing checkout becomes privileged because the trigger changed, and when the
pattern appears inside a local action or reusable workflow the job uses. A
version bump of a download action is quiet.

A checkout that puts only documentation in the workspace is not reported when
nothing later in the job can execute or interpret it: a sparse checkout with
`sparse-checkout-cone-mode: false` that lists only Markdown, reStructuredText or
AsciiDoc files, or files named README, LICENSE, COPYING, NOTICE, AUTHORS or
CHANGELOG, followed only by `actions/checkout` or `actions/upload-artifact`
steps. Each condition matters: in cone mode Git also checks out every file at
the repository root; wildcards and other files (including `requirements.txt`)
can be build input; a later script could restore the whole tree; and any other
action, local or external, may render, template or run what it reads, so its
behaviour is treated as unknown. A documentation-only checkout inside a
composite action is still reported, since the calling job's later steps aren't
visible there.

The finding states what Remit saw: the content brought in, the trigger and what
the job has. It says the content can be executed only when a later step in the
same steps list runs a script or a local action, or when the script that fetched
it also runs other commands (anything but `git`, `gh` and a few shell built-ins);
it names that step and records it as `runBy`. Only then does it add that the code
can write to the Actions cache of the branch the workflow runs on, which later
trusted runs may restore. Without such a step it asks the reviewer to check
whether the actions that follow execute or interpret the files.

A pull request reference is followed to where it is used through:

- environment variables at workflow, job and step level (`${{ env.X }}`, or
  `$X` / `${X}` on the script line), and variables written to `$GITHUB_ENV`.
  Replacing a variable with a fixed value (`REF: main`, `echo "REF=main" >>
  "$GITHUB_ENV"`) or with `github.sha`, `github.ref`, `github.ref_name`,
  `github.base_ref`, the repository's default branch or the pull request's base
  clears it; a step's own `env:` does so for that step only. A replacement Remit
  can't resolve (an input, a variable, command output) keeps the earlier value;
- step outputs written to `$GITHUB_OUTPUT` or with `core.setOutput()` in
  `actions/github-script` (`${{ steps.id.outputs.x }}`);
- job outputs, for jobs that list the producing job in `needs`
  (`${{ needs.job.outputs.x }}`);
- inputs passed to local composite actions and reusable workflows
  (`${{ inputs.x }}`), and a composite action's outputs back to the caller.

Pull request data looked up while the job runs (`gh pr view`, `gh api …/pulls`)
counts as pull request content. For WF011 it counts as mutable, because the
lookup happens after the approval. The finding shows where the value came from,
for example `${{ env.SHA }} (from github.event.pull_request.head.sha)`. Values
built in other ways, such as string manipulation in a script or files passed
between jobs, are not traced.

## WF011: mutable reference after approval (TOCTOU)

Some privileged workflows wait for a maintainer first: a label
(`types: [labeled]` or a label check in `if:`), an environment approval, or a
comment command from a checked commenter. If the
job then checks out a pull request reference that can move — a branch name
(`head.ref`, `github.head_ref`, `workflow_run.head_branch`), `refs/pull/N/head`, the
head repository's default branch, or `gh pr checkout` — the author can push new
commits after the approval and before the checkout. The code that runs is not the
code that was reviewed.

Anyone who can see a public repository can comment, so an `issue_comment` job
counts as gated only when the job, or a job it lists in `needs`, checks who
commented: an `if:` on `author_association`, `user.login` or `github.actor`, a
collaborator permission lookup (`getCollaboratorPermissionLevel`,
`…/collaborators/…/permission`), or a slash-command action with a `permission`
or `permission-level` input. A check of the comment's text alone, such as
`contains(github.event.comment.body, '/ok-to-test')`, is not a gate, and a pull
request checkout there is WF010.

WF011 replaces WF010 for these cases. Checking out the immutable
`github.event.pull_request.head.sha` (or `workflow_run.head_sha`) is not TOCTOU
and stays WF010, since the job still runs pull request code with privileges.
The `issue_comment` event carries no pull request commit, so for comment
commands the fix is to have the command name the approved commit SHA and check
out exactly that.

## WF012: Actions cache in a privileged job

Pull request code that runs in a `pull_request_target`, `workflow_run` or
`issue_comment` job shares the Actions cache of the branch the workflow runs on,
and can write entries to it. A job that later restores that cache while it
publishes, deploys or holds secrets builds with whatever was planted. WF012 is
reported when a job with write scopes, `id-token: write`, secrets or an
environment, or any job in a dedicated release workflow (one that runs on
`release` or pushed tags, and otherwise only by hand), newly restores files from
the cache:

- `actions/cache` or `actions/cache/restore` (`actions/cache/save` only writes);
- `actions/setup-node`, `setup-python` or `setup-java` with a `cache:` input;
- `actions/setup-node` v5 or later without `package-manager-cache: false`, which
  caches npm when `package.json` names npm as its `packageManager`;
- `actions/setup-go` with `cache: true`, or v4 or later unless `cache: false`;
- `actions/setup-dotnet` with `cache: true`, `ruby/setup-ruby` with
  `bundler-cache: true`, `astral-sh/setup-uv` with `enable-cache: true`,
  `Swatinem/rust-cache`, and `gradle/actions/setup-gradle` unless
  `cache-disabled: true`.

So a version bump that turns caching on, such as `setup-node@v4` to `@v5`, is
reported. A version that can't be read from the reference (a SHA or a branch)
is not assumed to turn on a default. Changing what is cached by an action that
already cached (`cache: npm` to `cache: pnpm`) is quiet, and so is a job that
gains privileges while it already used the cache (WF001 or WF004 report that).
Steps in local composite actions count, with the finding on the action file.

## WF013: checkout keeps the token

`actions/checkout` keeps the job's token for later Git commands unless
`persist-credentials: false` is set. Before v6 it is written to the
repository's `.git/config`, where a later step can read it and a workspace
upload can publish it; from v6 it is kept in a file outside the workspace, still
readable by later steps. WF013 is reported when a checkout in a job (matched by
its `repository` and `path` inputs) had `persist-credentials: false` and no
longer does, including when the value becomes an expression. It applies when the
token is worth taking: the job can write, uses the repository's default
permissions, or passes a custom `token:`. Checkout v1 did not keep the token, and
a new checkout without the setting is quiet.

## Local code

Steps are followed into code the repository itself provides:

- local composite actions, `uses: ./path` (reading `path/action.yml` or
  `action.yaml`; JavaScript and Docker local actions are not followed);
- local reusable workflows, `uses: ./.github/workflows/name.yml`, whose jobs run
  with the calling job's permissions and secrets.

GitHub's same-repository form, `uses: $/path`, is followed the same way and is
never reported as third-party code.

A `uses: ./path` step reads from the workspace, so earlier `actions/checkout` steps
in the job are taken into account when their inputs are literal:

- this repository checked out into a folder (`path: tools`) makes
  `./tools/.github/actions/x` this repository's `.github/actions/x`;
- another repository (`repository: owner/other`) checked out into a folder, or at
  the workspace root, makes the actions under it third-party code from that
  repository (WF009).

References are followed up to ten levels deep, GitHub's own limit, cycles are
cut, and paths that leave the repository are refused. A workflow whose own file didn't change is
still examined when a local file it reaches did. A local reference that can't be
read or parsed makes the analysis `incomplete` for every job that reaches it. Actions and reusable workflows from other
repositories are not fetched.

## Matrices and expressions

Expressions are not evaluated, with one narrow exception: a `workflow_run` job's
`if:` (or that of a job it needs) is checked for whether it rules out runs caused
by pull requests. If the condition is definitely false whenever
`github.event.workflow_run.event` is a pull request, review, comment, merge queue
or `workflow_run` event, as with `github.event.workflow_run.event == 'push'`, the
job can't receive pull request content through that trigger and WF010/WF011 stay
quiet for it. Anything that can't be decided, such as a function call or another
property, counts as possibly true, so the check only ever errs toward reporting.
So does a comparison between values of different types: GitHub converts those to
numbers, which makes `1 == '1'`, `null == ''` and `'0x1' == 1` true, and Remit
doesn't try to reproduce that.
A `workflow_run` `branches:` filter is not enough on its own: a fork's pull request
can come from a branch with the same name.

A `runs-on`, runner group or `environment` value
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
