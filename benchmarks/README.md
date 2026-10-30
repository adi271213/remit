# Historical public-PR regression replay

The manifest contains **74 selected public PR pairs**, exact commit IDs, complete
immediate workflow-file inventories for both sides, SHA-256 content hashes,
immutable source URLs and 45 expected legacy WF001/WF003/WF004 finding facts.
Selection was purposeful and correlated (2021–2026), not a random or malicious-PR
corpus. The implementing assistant assigned the original labels; they are not
independent human judgments. Legitimate hardening/migrations can be positives.
The note on each case records known context/validity caveats.

Install development dependencies, then run:

```sh
python scripts/replay_benchmark.py --cache .benchmark-cache
# Reuse the hash-verified inputs with no network:
python scripts/replay_benchmark.py --cache .benchmark-cache --offline
# Download and check only one pair first:
python scripts/replay_benchmark.py --cache .benchmark-cache --limit 1
```

The first run downloads public workflow files as data; it does not execute them.
Cache entries are content-addressed and reverified on every replay. Missing,
oversized or hash-mismatched input fails the replay; it is never treated as a
clean case. `manifest.sha256` protects the exact case inventory. Generated output
and cache are ignored by Git. The source files remain under upstream licenses.

`benchmark-results.json` records every actual report, verifies the **legacy exact
facts**, and separately lists findings from newer rules. A zero replay exit means
those historical facts match, not that every new finding is correct or useful.
WF005/WF007 were not part of the original labels; their findings are not silently
promoted to independently adjudicated positives.

At the 0.0.0 candidate, the replay preserves all 45 legacy facts and the same
62 complete / 12 incomplete outcomes. It adds one WF007 environment-context
finding. This is a regression observation, not precision/recall, superiority over
other tools, or a usefulness result. It does not substitute for the synthetic
context regressions and hosted Action checks described in [validation](../VALIDATION.md).
