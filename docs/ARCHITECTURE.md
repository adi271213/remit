# Architecture and trust boundaries

The scanner compares supported configuration in two snapshots. It does not
execute a workflow or determine whether a PR is safe.

## Data flow

1. `scripts/run-action.sh` starts the controller with isolated Python imports.
   `scripts/action_runner.py` verifies the bundled PyYAML files, creates job-local
   report paths and runs the scanner in a child process with a timeout.
2. `scripts/action_entry.py` reads explicit commit SHAs or PR event metadata and
   invokes the CLI. Default-permission assertions come from the trusted caller.
3. `src/privilege_check/sources.py` reads bounded workflow files from directories
   or local Git objects. Git reads ignore replacement refs and caller `GIT_*`
   redirections. Missing objects are errors; this layer does not fetch them.
4. `scan.py` skips unchanged files, matches exact-content renames, parses changed
   YAML and compares supported fields per job. `yaml_limits.py` bounds the whole
   composed graph before construction. `contexts.py` handles runner/environment
   normalization and bounded static matrices. The association rule
   retains runner/environment bindings from each row when comparing unchanged
   individual target sets.
   `expressions.py` shares the supported identifier grammar between secret
   reference scanning and direct matrix selection; neither evaluates expressions.
5. `report.py` escapes repository-controlled text for Markdown. The CLI emits
   JSON or Markdown. The Action controller publishes explicit analysis/review
   outcomes, report paths and a job summary.

## Trusted code and proposed data

The copy-ready workflow checks out the PR base, fetches the proposed head without
checking it out, verifies it matches the event and invokes a full-SHA-pinned
Action. Workflow blobs are data. No script, local action or Python module from
the proposed head is loaded by the scanner.

The calling workflow itself can be edited in a PR. A pinned scanner does not make
that workflow an unbypassable boundary. Keep normal workflow review, fork approvals
and read-only permissions. The public setup is for Linux GitHub-hosted runners;
private authentication and arbitrary self-hosted installations need separate
validation.

## Outcome contract

`complete` means the supported comparison finished under its disclosed
assumptions. Unchanged inherited defaults and unresolved selectors can compare
symbolically when their external context is assumed fixed. `complete` does not
mean that every execution path or external setting was inspected.

`incomplete` records missing context. `error` records invalid/unsupported input or
an execution failure. Known findings remain available where their comparison was
established. The Action reports `none` only for complete analysis without findings;
it reports `unknown` for unresolved analysis without findings.

Findings suggest human review in both modes. `require-complete` fails unresolved
analysis; `advisory` reports it without failing. Neither mode enforces approval of
findings. Missing outputs or publication failures are execution failures, not
clean results. See [outcomes](../README.md#outcomes) and [coverage policies](../README.md#coverage).
