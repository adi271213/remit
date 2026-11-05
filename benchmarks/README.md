# Historical PR replay

`manifest.jsonl` lists 74 public pull requests from 2021–2026 that changed GitHub
Actions workflows. For each one it records the exact base and head commits, every
workflow file on both sides with its SHA-256 and source URL, and the expected
WF001, WF003 and WF004 findings (39 in total). `manifest.sha256` pins the manifest.

```sh
# Download inputs (hash-checked) and replay
python scripts/replay_benchmark.py --cache .benchmark-cache
# Replay from the cache only
python scripts/replay_benchmark.py --cache .benchmark-cache --offline
# Try a single case first
python scripts/replay_benchmark.py --cache .benchmark-cache --limit 1
```

Workflow files are downloaded from `raw.githubusercontent.com` and treated as
data. Any missing, oversized or mismatched file fails the replay. Results go to
`benchmark-results.json`; the expected summary is in `expected-summary.json`.

The replay passes when every expected WF001/WF003/WF004 finding matches exactly.
Findings from later rules (WF005 onwards) are reported separately in the summary
but are not checked.

## Comparison with zizmor

`scripts/compare_zizmor.py` runs [zizmor](https://github.com/zizmorcore/zizmor)
(pedantic persona, offline) on the base and head of every case with findings. A
finding counts as also surfaced when zizmor reports more findings of a related
audit for the same workflow file and job at the head than at the base, which
approximates what code scanning would show as new on the PR.

| Rule | Findings | Also surfaced by zizmor |
|---|---|---|
| WF001 | 23 | 9 |
| WF002 | 14 | 4 |
| WF003 | 8 | 6 |
| WF004 | 8 | 0 |
| WF007 | 1 | 0 |
| WF009 | 11 | 3 |
| WF012 | 1 | 1 |
| **Total** | **64** | **23** |

Remit reports 66 findings on these PRs. zizmor crashed on both sides of one
(grafana/grafana#89410), so its 2 findings are left out of the table rather than
counted as missed by zizmor. An earlier version of the script read a crash as
"no findings" and published 43 of 65 as not surfaced by zizmor; with the crash
left out it is 41 of 64.

Measured with zizmor 1.32.0. Online audits were skipped, and code scanning
matches alerts by fingerprint rather than count, so treat these numbers as an
approximation.

**Caveats.** The cases were chosen by hand rather than sampled, and the expected
findings were labelled by the project rather than by independent reviewers. Some
positives are intentional hardening changes. Use the replay to catch
regressions, not as a measure of precision or recall. The source files remain
under their upstream licenses.

## Field comparison: 446 commits in 30 repositories

The replay above was chosen by hand and Remit was developed against it. The field
comparison uses repositories and commits picked by a rule instead, and puts
Remit next to [zizmor](https://github.com/zizmorcore/zizmor),
[poutine](https://github.com/boostsecurityio/poutine) and
[actionlint](https://github.com/rhysd/actionlint).

**Selection.** For each of Python, JavaScript, TypeScript, Go, Rust and Java, the
most-starred repositories (GitHub search, November 2026), skipping the replay's
repositories and any with fewer than 10 commits touching `.github/` in the past
year, until five qualified: [`field/repositories.tsv`](field/repositories.tsv).
In each, the last 15 first-parent commits on the default branch that touched
`.github/`, compared with their parent: [`field/commits.tsv`](field/commits.tsv).

**Method.** `.github/` and every `action.yml` are checked out on both sides.
Remit compares them; zizmor (1.32, pedantic, offline), poutine and actionlint
(1.7.12) run on each side, and only findings that are new at the commit count.
A tool that exits with an error or prints output that can't be read is recorded
as failed for that commit, and left out of its counts rather than counted as
finding nothing.
[`scripts/field_comparison.py`](../scripts/field_comparison.py) reruns it and
summarizes ([`field/summary.json`](field/summary.json)). The numbers below are
from the current code; no tool failed on these commits.

| | Remit | zizmor | poutine | actionlint |
|---|---|---|---|---|
| Commits with new findings | 60 | 79 | 26 | 13 |
| New findings | 233 | 469 | 53 | 66 |
| Main subject | privilege increases | risky patterns: injection, pinning | supply chain | correctness |

Of Remit's 233 findings, 61 had a related new finding from zizmor or poutine in
the same file and job (a rule aimed at the same risk); 172 did not. By rule:

| Rule | Findings | Related new finding elsewhere |
|---|---|---|
| WF001 token scope increase | 53 | 20 |
| WF002 default permissions | 7 | 6 |
| WF003 review-sensitive trigger | 13 | 7 |
| WF004 new secret | 57 | 2 |
| WF005 runner selection | 31 | 0 |
| WF007 environment | 13 | 0 |
| WF009 third-party code with privileges | 35 | 23 |
| WF010 pull request content | 1 | 0 |
| WF012 cache in a privileged job | 23 | 3 |

WF012 was added after this comparison was first run (see "Second review" below),
so it was not tuned on these commits. Its 23 findings include a publishing job
with `id-token: write`, a release job holding a GitHub App private key, release
and deploy jobs with write access, and a job turning on `setup-node`'s automatic
cache by moving to v6; 3 matched a new zizmor `cache-poisoning` finding. Without
WF012 the totals are 210 findings and 152 with no related finding elsewhere (211
and 151 in the first published run). zizmor reported 16 fewer `artipacked`
findings than in the first run, on 5 commits; that difference was not traced.

Every privilege change that zizmor reported as new (excessive permissions,
dangerous triggers, self-hosted runners, inherited secrets) was also reported by
Remit, except in one commit whose workflow file was invalid. In a hand-checked
random sample of 30 Remit findings, 29 were correct and worth a reviewer's look.

**What it changed.** The first run found 279 Remit findings, 62 of them new jobs
declaring read-only scopes, plus wrong or repeated findings, and 55 commits
without a complete analysis. The fixes listed in the changelog's Unreleased
section brought that to 211 findings and 30 commits. What keeps those 30
incomplete can't be known from the repository: runners chosen by expressions
(20 commits), code fetched into the workspace by shell scripts (11), an action
that is not in the repository (2) and an invalid file (1); some commits have two
of these.

**Audit mode.** On each repository's current default branch, `remit audit`
reported WF010 in 6 repositories (10 jobs). Checked by hand, 9 bring pull request
content into a privileged job: three `pull_request_target` jobs that check out the
pull request head, an upload of pull-request-built tarballs with
`id-token: write`, a job limited to trusted commenters, and four that only post a
comment from a downloaded artifact. One is not reachable from a pull request; its
job uses `always()`, which Remit treats as able to bypass the gate.
poutine's `untrusted_checkout_exec` reported 252 findings, 194 of them in one
repository. Of 15 flagged jobs inspected in the others, 3 were the same
`pull_request_target` jobs Remit reported; the other 12 checked out trusted code
(the base branch, a tag, or a reusable workflow's input). poutine did not report
the artifact and tarball cases.

**Caveats.** Findings were judged by this project, not independent reviewers.
Matching between tools by file and job is approximate. zizmor ran with its
strictest persona, which raises its counts. Some of the most-starred
repositories have unusual star counts, but the rule was applied as written.

## Held-out validation

The field comparison above found problems that were then fixed, and the fixed
version was measured on the same commits, so it could flatter Remit. This
validation was written down first ([`heldout/PROTOCOL.md`](heldout/PROTOCOL.md):
selection rules, measures and targets) and run once on code frozen at the time
(`d962893`). Results are reported as measured, including targets that were missed.

### 1. Thirty repositories Remit had never been run on

Same rule as the field comparison, continued down the same star-sorted lists:
[`heldout/repositories.tsv`](heldout/repositories.tsv) (among them transformers,
vscode, n8n, rust-lang/rust, deno, guava, three.js, hugo) and 448 commits,
[`heldout/commits.tsv`](heldout/commits.tsv). Summary:
[`heldout/summary.json`](heldout/summary.json).

| Measure | Target | Result |
|---|---|---|
| Crashes | 0 | 0 |
| Commits with complete analysis | ≥ 90% | 97.5% (437 of 448; 2 errors are workflows with duplicate keys, which GitHub rejects too) |
| Wrong findings, random sample of 40 | ≤ 5% | 0% |
| Correct but not worth a reviewer's time, same sample | ≤ 15% | 15–20%: missed |
| Time per commit, p95 / max | < 5 s / < 60 s | 1.2 s / 1.6 s |

Remit reported 277 findings. zizmor crashed on 15 commits (13 in
microsoft/vscode), which carry 14 of those findings; the first version of the
script counted a crash as zero findings and published 188 as having no related
new finding from zizmor or poutine. Leaving those commits out of the comparison,
176 of the other 263 had none ([`heldout/summary.json`](heldout/summary.json)). Every new privilege finding from zizmor (excessive permissions,
dangerous triggers, self-hosted runners, inherited secrets) was also reported
by Remit. poutine newly reported 11 untrusted checkouts that Remit did not;
by hand, all were reusable workflows called from `pull_request` CI, which gets
no secrets for forks, not privileged runs.

The missed target came from WF002: a new job using the default token in a
workflow whose jobs already did (20 findings), and default permissions replaced
by a read-only block (21). Both are hardening or no change; Remit is now quiet
for them (changelog, Unreleased). That change is motivated by these
repositories, so its effect needs a further held-out set to be measured fairly.

### 2. Planted changes

[`scripts/planted_changes.py`](../scripts/planted_changes.py) takes real jobs from
the held-out repositories at the commits in
[`heldout/planted-corpus.tsv`](heldout/planted-corpus.tsv) and plants one change:
19 kinds that must be reported (write scopes, OIDC, removed permissions, new
triggers, secrets, self-hosted runners, environments, third-party actions in the
job or inside a local composite action, and ten ways to bring pull request content
into a privileged job: direct checkouts, an env variable, a step output, `gh pr
checkout`, `git fetch` of `refs/pull`, `gh pr diff | git apply`, a `workflow_run`
artifact, a composite action input) and 6 kinds that must not be (a renamed step,
an action version bump, a new read-only job, a hosted runner upgrade, a
`pull_request_target` checkout of the base, and a `workflow_run` checkout gated
to push runs). Up to 150 jobs per kind, 3,718 cases. (This is the first run, on
the frozen code; the second review below adds kinds for WF012 and WF013 and
reruns it with stricter matching.)

Every planted change was reported and no benign one was: 100% for each of the
25 kinds. The first run was lower for five kinds (77% to 99%); each miss or
false alarm was traced by hand to the harness, not Remit: it counted
`secrets.GITHUB_TOKEN` as a privilege, planted fetches in jobs that already had
one, left conditions on needed jobs that made the planted step unreachable,
called a new job benign where the workflow's `env:` passes it a secret, and
edited one job's steps where YAML aliases shared them with other jobs. In every
case Remit's answer was the correct one.

These are the patterns Remit was built to catch, so the test shows they work
across real workflow shapes (anchors, matrices, nested and reusable
workflows); it does not measure patterns nobody anticipated. It also showed a
documented limit: a third-party action in a job that inherits default
permissions is not WF009 unless the job has secrets or an environment, because
the token's permissions are unknown. `default-permissions` resolves it.

### 3. Robustness

**Fuzzing** ([`scripts/fuzz_workflows.py`](../scripts/fuzz_workflows.py)) on
workflows from the field repositories
([`field/fuzz-corpus.tsv`](field/fuzz-corpus.tsv)). On the frozen code it found
one problem: three patterns that scan script lines and expressions backtracked
on long, specially shaped text, so a 200 KB line in a pull request took about
120 s of CPU, enough to time the Action out (the check then fails; nothing is
silently passed). They are now linear scans with identical results, checked
against the old patterns on 300,000 random strings; a 1 MB hostile line takes
about 1.6 s. On the fixed code, 20,000 inputs (four seeds of 5,000) gave no failures: no exceptions, no reports inconsistent with their diagnostics, no output differing between runs, and at most 12 s of CPU for one call, on a mutated workflow from the largest repository. 500 CLI runs on files mutated on disk
(invalid UTF-8, BOMs, oversized files, symlinks, 450 workflow files) all exited
with a valid code and a JSON report.

**Coverage** under the test suite: 91% of lines and branches in `src/remit`.
It showed one unused method (removed) and `merge_base`, used by the Action to
compare from where a pull request branched, without a direct test (added).

## Second review (November 2026)

An outside review found six problems:

- a comparison across types could hide a pwn request;
- documentation-only checkouts were trusted too far;
- overwritten variables kept their pull request taint;
- WF010's message claimed more than Remit saw;
- the benchmark scripts read a crashed tool as "no findings";
- there were no checks for cache use and `persist-credentials`.

All six are fixed (changelog, Unreleased). The benchmark fixes changed published
numbers, and those are corrected above.

**Does the new version make anything worse?** The previous `main` (`168056f`) and
the new version ran side by side on all 894 field and held-out commits, both as
a pull request scan and as an audit of the head:

| | Field (446 commits) | Held-out (448 commits) |
|---|---|---|
| Findings that disappeared | 0 | 0 |
| Crashes, or analysis no longer complete | 0 | 0 |
| New scan findings | 23, all WF012 | 21, all WF012 |
| New audit findings | 36 WF010, all in deepseek-ai/deepseek-harness | 0 |
| Time per commit, p95 (old / new) | 2.17 s / 2.22 s | 1.01 s / 1.05 s |

The deepseek findings are the documentation-only checkouts followed by an
external action. They were quiet in the previous version and are reported again
on purpose. The message now says that Remit saw no step running the content, and
asks the reviewer to check the action. The replay of 74 PRs gained one WF012
finding and nothing else.

**Planted changes, rerun.** The test now counts a detection only when the rule,
file, workflow and job all match the planted change; before, any finding with
the right rule and job name counted. It also has new kinds:
- three that must be reported: a cache restore in a privileged job, `setup-node`
  v4 to v5 (which turns on its npm cache), and `persist-credentials: false`
  removed;
- two that must not be: `persist-credentials: false` added, and a cache in a
  read-only job.

That makes 22 kinds that must be reported (3,268 cases) and 8 that must not be
(1,141 cases). Every planted change was reported, and no benign change was.

On the way there were two harness errors, each traced by hand, with Remit
right both times:
- One cache restore was "missed" because the job already restored a cache with
  the same action inside a nested local action. Adding a second one is no
  change.
- Eight "false alarms" in read-only jobs were Remit applying its rule as
  documented. Five were reusable workflows whose callers pass them secrets
  (`secrets: inherit`), reported at the caller. Three were dedicated release
  workflows.

The harness now skips both kinds of job for that benign case. Before that, the
benign case scored 104 of 112.

**Fuzzing** of the new version: Atheris ran 159,000 inputs, and the mutation
fuzzer 2,000 inputs (two seeds), with no failures.

