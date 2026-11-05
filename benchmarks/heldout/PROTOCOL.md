# Validation protocol (written before any test was run)

Code under test: remit at main d962893, frozen. No changes to Remit until all three
tests have been measured and reported. Results are reported whatever they show.

## 1. Held-out repositories

Selection: same rule as the field comparison, continued. For each of Python,
JavaScript, TypeScript, Go, Rust, Java: GitHub search `language:X stars:>20000
pushed:>2026-10-01 archived:false`, sorted by stars, pages 1-3. Skip the 30 field
repositories, the 14 replay repositories, forks, and repositories with fewer than
10 first-parent commits touching .github/ since 2025-11-05. Take the next 5 that
qualify. Commits: the last 15 first-parent commits touching .github/ on the default
branch, each against its parent. Tools: Remit (with --repository-name), zizmor 1.32
pedantic offline, poutine, actionlint 1.7.12.

Measured, once:
- crash count (target 0);
- share of commits with complete analysis (target >= 90%);
- in a random sample of 40 Remit findings (seed 2026), the share that are wrong
  (target <= 5%) and the share that are correct but not worth a reviewer's time
  (target <= 15%); classified before looking at other tools' output for that commit;
- overlap with zizmor/poutine using the strict rule mapping in field_comparison.py;
- p95 and max Remit seconds per commit (target p95 < 5 s, max < 60 s).

## 2. Planted changes (detection rate)

Corpus: workflows at the default-branch HEAD of the held-out repositories. A
development run on the 30 field repositories is allowed only to debug the harness.

Each mutation introduces exactly one change of a known kind into a real job; base is
the workflow re-serialized unchanged, head is the same with the mutation, both written
with the same serializer. Detection = the expected rule on the expected file (and job,
where the rule has one), in the expected analysis outcome or an incomplete one
(reported separately). Up to 150 applicable sites per operator, seed 2026.

Privilege mutations (must be reported): new write scope, new id-token: write, removal
of an explicit permissions block (WF002), new review-sensitive trigger, new secret
reference, self-hosted runner, new environment, new third-party action in a
privileged job, the same action added inside a local composite action, and pull
request content in a privileged job through: direct checkout of head.ref and
head.sha, github.head_ref, an env variable, a step output, gh pr checkout, git fetch
of refs/pull, gh pr diff | git apply, a workflow_run artifact download, and a local
composite action input.
Targets: >= 95% for each direct operator; >= 90% for each indirect one.

Benign mutations (must stay quiet): renamed step, version bump of an existing
third-party action, new read-only job, ubuntu-22.04 -> ubuntu-24.04, a
pull_request_target checkout of github.sha, a workflow_run checkout of head_sha gated
to push runs. Target: false-alarm rate <= 2% per operator.

## 3. Robustness

- Fuzzing: at least 20,000 inputs derived from real workflows (structural mutations:
  deleted keys, swapped types, odd scalars, deep nesting, aliases, duplicate keys,
  long strings, unicode; and byte-level mutations), run through compare() and
  audit(), plus 500 through the CLI. Failure = an exception escaping the API, a CLI
  exit code outside {0, 1, 2}, non-JSON output, a report whose analysis disagrees
  with its diagnostics, non-deterministic output, or more than 30 s for one input.
  Target: 0 failures.
- Coverage: line and branch coverage of src/remit under the test suite, reported
  as measured, with the largest uncovered areas listed.
