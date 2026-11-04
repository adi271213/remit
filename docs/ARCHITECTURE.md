# Architecture

## Modules

| Path | Responsibility |
|---|---|
| `scripts/run-action.sh` | Action entry point. Starts the controller with `python3 -I` so nothing is imported from the checked-out repository or `PYTHONPATH`. |
| `scripts/action_runner.py` | Stdlib-only controller. Verifies the bundled PyYAML against its SHA-256 manifest, runs the scanner in a child process with a 90 s timeout, checks the report is consistent with the exit code, and publishes outputs and the job summary. Any setup failure still produces an explicit `error` report. Findings become line annotations; all repository-controlled text in commands is escaped, and the report is printed between `::stop-commands::` markers. |
| `scripts/action_entry.py` | Resolves base/head SHAs from inputs or the PR event and calls the CLI. |
| `src/privilege_check/cli.py` | Argument parsing, report output, exit codes. |
| `src/privilege_check/sources.py` | Reads workflow files from a directory or from Git objects, with size limits. |
| `src/privilege_check/scan.py` | YAML parsing, rename detection, WF001/WF003/WF004, and assembly of the report. |
| `src/privilege_check/contexts.py` | WF005/WF007/WF008: runner and environment normalisation and matrix expansion. |
| `src/privilege_check/expressions.py` | Identifier grammar shared by secret and matrix parsing. |
| `src/privilege_check/yaml_limits.py` | Bounds the composed YAML graph before any Python objects are built. |
| `src/privilege_check/report.py` | Markdown rendering with all repository-controlled text escaped. |

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

Input limits: 200 workflow files and 4 MiB per snapshot, 256 KiB per file,
strict UTF-8 (a BOM is allowed).

Errors from PyYAML include source text, so they're replaced with a generic
message in the report.

## Report

```text
schemaVersion        report format version, independent of the package version
base, head           commit SHAs, or directory content hashes for --dirs
analysis             complete | incomplete | error
review               none | suggested
findings[]           rule, file, job, line, before, after, message
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
`analysis` is `error` if any diagnostic is an error, `incomplete` if any is
incomplete, otherwise `complete`.
