"""Compare this tool's findings with the new findings zizmor reports for the same PRs.

For each replay case with findings, zizmor runs on the base and head workflows.
A finding counts as also surfaced when zizmor reports more findings of a related
audit for the same workflow file and job at the head than at the base. This
approximates what zizmor plus GitHub code scanning would show as new on the PR.

Needs `zizmor` on PATH and a populated replay cache (run replay_benchmark.py first).
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from remit.scan import compare  # noqa: E402
from remit.sources import Snapshot  # noqa: E402

# zizmor audits that address the same risk as each rule.
RELATED = {
    "WF001": {"excessive-permissions"},
    "WF002": {"excessive-permissions"},
    "WF003": {"dangerous-triggers"},
    "WF004": {"secrets-outside-env", "secrets-inherit", "overprovisioned-secrets", "unredacted-secrets"},
    "WF005": {"self-hosted-runner"},
    "WF007": set(),
    "WF008": set(),
    "WF009": {"unpinned-uses", "archived-uses", "known-vulnerable-actions", "impostor-commit", "ref-confusion"},
}


def zizmor_findings(files, folder):
    """Counter of (audit, workflow path, job) for zizmor's pedantic, offline findings."""
    if not files:
        return Counter()
    for path, text in files.items():
        target = folder / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    result = subprocess.run(["zizmor", "--offline", "--persona", "pedantic", "--no-config", "--format", "json",
                             str(folder / ".github/workflows")], capture_output=True, text=True, check=False)
    found = Counter()
    for item in json.loads(result.stdout or "[]"):
        location = item["locations"][0]["symbolic"]
        path = ".github/workflows/" + Path(next(iter(location["key"]["Local"].values()))).name
        route = location.get("route", {}).get("route", [])
        job = route[1].get("Key") if len(route) > 1 and route[0].get("Key") == "jobs" else None
        found[(item["ident"], path, job)] += 1
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".benchmark-cache")
    parser.add_argument("--output", type=Path, default=ROOT / "zizmor-comparison.json")
    args = parser.parse_args()
    version = subprocess.run(["zizmor", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    rows = []
    for line in (ROOT / "benchmarks/manifest.jsonl").read_text().splitlines():
        case = json.loads(line)
        files = {"base": {}, "head": {}}
        for file in case["files"]:
            files[file["side"]][file["path"]] = (args.cache / file["sha256"]).read_bytes().decode("utf-8-sig")
        ours = compare(Snapshot(case["base"], files["base"]), Snapshot(case["head"], files["head"]))["findings"]
        if not ours:
            continue
        with tempfile.TemporaryDirectory() as temp:
            base = zizmor_findings(files["base"], Path(temp) / "base")
            head = zizmor_findings(files["head"], Path(temp) / "head")
        new = {key for key, count in head.items() if count > base.get(key, 0)}
        for finding in ours:
            related = sorted(audit for audit, path, job in new
                             if audit in RELATED[finding["rule"]] and path == finding["file"]
                             and (finding["job"] is None or job in (finding["job"], None)))
            rows.append({"pr": case["pr"], "rule": finding["rule"], "file": finding["file"], "job": finding["job"],
                         "after": finding["after"], "zizmorNew": related})
    totals = defaultdict(lambda: [0, 0])
    for row in rows:
        totals[row["rule"]][0] += 1
        totals[row["rule"]][1] += bool(row["zizmorNew"])
    summary = {"zizmor": version, "findings": len(rows), "alsoSurfacedByZizmor": sum(v[1] for v in totals.values()),
               "byRule": {rule: {"findings": n, "alsoSurfacedByZizmor": z} for rule, (n, z) in sorted(totals.items())}}
    args.output.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
