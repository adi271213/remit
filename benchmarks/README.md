# Historical PR replay

`manifest.jsonl` lists 74 public pull requests from 2021–2026 that changed GitHub
Actions workflows. For each one it records the exact base and head commits, every
workflow file on both sides with its SHA-256 and source URL, and the expected
WF001, WF003 and WF004 findings (45 in total). `manifest.sha256` pins the manifest.

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

**Caveats.** The cases were chosen by hand rather than sampled, and the expected
findings were labelled by the project rather than by independent reviewers. Some
positives are intentional hardening changes. Use the replay to catch
regressions, not as a measure of precision or recall. The source files remain
under their upstream licenses.
