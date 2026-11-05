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
Findings from later rules (WF005, WF007, WF008) are reported separately in the
summary but are not checked.

## Comparison with zizmor

`scripts/compare_zizmor.py` runs [zizmor](https://github.com/zizmorcore/zizmor)
(pedantic persona, offline) on the base and head of every case with findings. A
finding counts as also surfaced when zizmor reports more findings of a related
audit for the same workflow file and job at the head than at the base, which
approximates what code scanning would show as new on the PR.

| Rule | Findings | Also surfaced by zizmor |
|---|---|---|
| WF001 | 23 | 9 |
| WF002 | 15 | 4 |
| WF003 | 8 | 6 |
| WF004 | 8 | 0 |
| WF007 | 1 | 0 |
| WF009 | 11 | 3 |
| **Total** | **66** | **22** |

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
[`scripts/field_comparison.py`](../scripts/field_comparison.py) reruns it and
summarizes ([`field/summary.json`](field/summary.json)).

| | Remit | zizmor | poutine | actionlint |
|---|---|---|---|---|
| Commits with new findings | 55 | 82 | 26 | 13 |
| New findings | 211 | 485 | 53 | 66 |
| Main subject | privilege increases | risky patterns: injection, pinning | supply chain | correctness |

Of Remit's 211 findings, 60 had a related new finding from zizmor or poutine in
the same file and job (a rule aimed at the same risk); 151 did not. By rule:

| Rule | Findings | Related new finding elsewhere |
|---|---|---|
| WF001 token scope increase | 53 | 20 |
| WF002 default permissions | 8 | 8 |
| WF003 review-sensitive trigger | 13 | 7 |
| WF004 new secret | 57 | 2 |
| WF005 runner selection | 31 | 0 |
| WF007 environment | 13 | 0 |
| WF009 third-party code with privileges | 35 | 23 |
| WF010 pull request content | 1 | 0 |

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
