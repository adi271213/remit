# Architecture

## Modules

| Path | Responsibility |
|---|---|
| `scripts/run-action.sh` | Action entry point. Starts the controller with `python3 -I` so nothing is imported from the checked-out repository or `PYTHONPATH`. |
| `scripts/action_runner.py` | Stdlib-only controller. Verifies the bundled PyYAML against its SHA-256 manifest, runs the scanner in a child process with a 90 s timeout, checks the report is consistent with the exit code, and publishes outputs and the job summary. Any setup failure still produces an explicit `error` report. Findings become line annotations, most serious first, with the analysis status ahead of them; all repository-controlled text in commands is escaped, and the report is printed between `::stop-commands::` markers. |
| `scripts/action_entry.py` | Resolves base/head SHAs from inputs or the PR event and calls the CLI. |
| `src/remit/cli.py` | The `scan` and `audit` commands: argument parsing, report output, exit codes. |
| `src/remit/sources.py` | Reads workflow files from a directory or from Git objects, with size limits. |
| `src/remit/scan.py` | YAML parsing, rename detection, WF001–WF004 and WF009–WF013, and assembly of the report. |
| `src/remit/flows.py` | What code a job runs: third-party actions and fetches of pull request content, followed into local composite actions and reusable workflows. |
| `src/remit/shell.py` | A one-pass reader of script lines: words, quotes and command substitutions, the subcommand of a `git` command, and the name of a branch that `git checkout -b` creates. Linear in the line's length. |
| `src/remit/checkouts.py` | WF013: matches each `actions/checkout` step to the same step on the base side (by id, then by position among unchanged steps) before comparing `persist-credentials`. |
| `src/remit/conditions.py` | Whether a `workflow_run` job's `if:` rules out runs caused by pull requests: a small parser and three-valued evaluator with size and nesting budgets. |
| `src/remit/contexts.py` | WF005/WF007/WF008: runner and environment normalisation and matrix expansion. |
| `src/remit/expressions.py` | Identifier grammar shared by secret and matrix parsing. |
| `src/remit/yaml_limits.py` | Bounds the composed YAML graph before any Python objects are built. |
| `src/remit/report.py` | Markdown rendering with all repository-controlled text escaped. |
| `src/remit/sarif.py` | SARIF 2.1.0 output with rule metadata and line-independent fingerprints. |

## Trust boundary

The copy-ready workflow checks out the PR's base commit and fetches the head
only as Git objects. The Action is pinned by SHA and loaded from GitHub, not from
the PR. Workflow files from the head are parsed as data; no script, action or
Python module from the PR is loaded.

The calling workflow itself lives in the repository and can be edited by a PR.
Pinning the scanner doesn't change that, so normal workflow review and fork
approval settings still matter.

### Reading Git objects

`sources.git_snapshot` runs `git rev-parse`, `ls-tree` and `cat-file` against
the given repository. It:

- drops every caller `GIT_*` environment variable, and ignores system and global
  Git config, replacement refs and `core.fsmonitor`;
- disables prompts and lazy fetching, so missing objects are an error rather than
  a network request;
- requires refs to resolve to a single full commit SHA;
- rejects symlinks and submodules under `.github/workflows`;
- applies a 15-second timeout to each Git call.

Local actions outside `.github/workflows/` are read on demand through the same
reader: at most 100 extra files and 16 MiB per snapshot, regular files only, and
no path that leaves the repository or passes through a symbolic link.

Git error output is never copied into the report.

## Parsing

YAML is loaded with a `SafeLoader` subclass that:

- keeps `on`, `yes`, `no` etc. as strings, so only `true`/`false` are booleans;
- rejects duplicate keys, non-string keys and merge keys (`<<`).

Before parsing, a token pass enforces at most 60,000 tokens, 500 aliases and
nesting depth 50. After composition, `yaml_limits.validate_graph` charges every
alias its full expanded cost and rejects the document if it exceeds 200,000
nodes, 4 MiB of scalar text or depth 50, or contains a cycle. This stops "billion
laughs" style inputs before any rule walks the data.

Input limits: 400 workflow files and 16 MiB per snapshot, 1 MiB per file,
strict UTF-8 (a BOM is allowed). A workflow file over 1 MiB is not read: it is
represented by a fingerprint of its content (its Git object ID, or a SHA-256 for
directories, which read at most 64 MiB), so an unchanged one compares equal and a
changed one makes that file `incomplete` without failing the rest.

Errors from PyYAML include source text, so they're replaced with a generic
message in the report.

## Report

```text
schemaVersion        report format version, independent of the package version
base, head           commit SHAs, or directory content hashes for --dirs
analysis             complete | incomplete | error
review               none | suggested
findings[]           rule, file, job, line, before, after, message; workflow when the finding
                     sits in a local action or reusable workflow; jobs[] ({workflow, job})
                     when one change there reaches several jobs
diagnostics[]        file, side, job, kind (incomplete | error), reason
renames[]            exact-content renames that were skipped
examinedFiles[]      files that changed and were compared
assumptions[]        symbolic comparisons made under a "context is unchanged" assumption
inheritedComparisons jobs compared under an unchanged inherited default
defaultPermissions   the supplied default map, if any
limitations[]        fixed list of what the analysis does not cover
action               (Action only) mode, reviewStatus, analysisExitCode
```

A diagnostic in one file or job doesn't hide findings established elsewhere.
In audit mode (`remit audit`), the comparison runs against an empty base and
keeps only WF010 and WF011; `mode` is `audit` and `base` is null. Only
diagnostics that can hide those rules (unreadable workflows or triggers, local
code that couldn't be followed) are kept. Local-code diagnostics carry
`area: local-code`.

`analysis` is `error` if any diagnostic is an error, `incomplete` if any is
incomplete, otherwise `complete`.
