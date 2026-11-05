"""Compare Remit with other workflow scanners on recent commits of public repositories.

For each commit in benchmarks/field/commits.tsv, the commit and its parent are fetched
(history and trees only; file contents on demand), .github/ and every action.yml are
checked out, and each tool runs on both sides. A state tool's findings count when they
are new at the commit; Remit compares the two sides itself.

    python scripts/field_comparison.py run --cache .field-cache --output field-results.jsonl
    python scripts/field_comparison.py run --commits benchmarks/heldout/commits.tsv --output heldout.jsonl
    python scripts/field_comparison.py summarize field-results.jsonl

zizmor, poutine and actionlint are used when they are on PATH. Network access to
github.com is needed for `run`.
"""
import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
COMMITS = ROOT / "benchmarks/field/commits.tsv"

# Other tools' rules aimed at the same risk as each Remit rule, for the overlap count.
RELATED = {
    "WF001": {"excessive-permissions", "default_permissions_on_risky_events"},
    "WF002": {"excessive-permissions", "default_permissions_on_risky_events"},
    "WF003": {"dangerous-triggers"},
    "WF004": {"secrets-inherit", "overprovisioned-secrets", "secrets-outside-env"},
    "WF005": {"self-hosted-runner", "pr_runs_on_self_hosted"},
    "WF007": set(),
    "WF008": set(),
    "WF009": {"known-vulnerable-actions", "impostor-commit", "archived-uses",
              "github_action_from_unverified_creator_used", "known_vulnerability_in_build_component"},
    "WF010": {"untrusted_checkout_exec"},
    "WF012": {"cache-poisoning"},
    "WF013": {"artipacked"},
    "WF011": {"untrusted_checkout_exec"},
}


def git(repo, *args, env=None):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, check=False)


def fetch(cache, slug, commit):
    repo = cache / slug.replace("/", "__")
    if not repo.exists():
        repo.mkdir(parents=True)
        git(repo, "init", "-q")
        git(repo, "remote", "add", "origin", f"https://github.com/{slug}")
        git(repo, "config", "remote.origin.promisor", "true")
        git(repo, "config", "remote.origin.partialclonefilter", "blob:none")
    if git(repo, "cat-file", "-e", f"{commit}^1").returncode:
        result = git(repo, "fetch", "-q", "--filter=blob:none", "--depth=2", "origin", commit)
        if result.returncode:
            raise RuntimeError(f"fetch {slug}@{commit[:8]} failed")
    return repo


def materialize(repo, commit, out):
    """.github/ and every action.yml/action.yaml at commit, under out."""
    names = git(repo, "ls-tree", "-r", "--name-only", commit).stdout.splitlines()
    paths = [n for n in names if n.startswith(".github/") or n.rsplit("/", 1)[-1] in ("action.yml", "action.yaml")]
    (out / ".github/workflows").mkdir(parents=True, exist_ok=True)
    if paths:
        with tempfile.TemporaryDirectory() as temp:
            env = {**os.environ, "GIT_INDEX_FILE": str(Path(temp) / "index")}
            result = git(repo, f"--work-tree={out}", "checkout", commit, "--", *paths, env=env)
            if result.returncode:
                raise RuntimeError(f"checkout of {commit[:8]} failed")


def relative(path, root):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


class ToolFailed(Exception):
    """A tool exited with an error or printed output that could not be read. Its findings for
    that commit are unknown, which is different from zero."""


def _execute(command, ok_codes, cwd=None):
    run = subprocess.run(command, capture_output=True, text=True, cwd=cwd, check=False)
    if run.returncode not in ok_codes:
        raise ToolFailed(f"exit {run.returncode}: {(run.stderr or run.stdout).strip()[-300:]}")
    return run


def _json(text):
    try:
        return json.loads(text)
    except ValueError as error:
        raise ToolFailed(f"unreadable output: {error}") from None


def zizmor(root):
    # 0: no findings; 10-14: findings, by highest severity. Anything else is an error.
    run = _execute(["zizmor", "--offline", "--persona", "pedantic", "--no-config", "--format", "json", str(root)],
                   {0, 10, 11, 12, 13, 14})
    found = Counter()
    items = _json(run.stdout)
    if not isinstance(items, list):
        raise ToolFailed("unexpected output")
    for item in items:
        location = item["locations"][0]["symbolic"]
        route = location.get("route", {}).get("route", [])
        job = route[1].get("Key") if len(route) > 1 and route[0].get("Key") == "jobs" else None
        found[(item["ident"], relative(next(iter(location["key"]["Local"].values())), root), job)] += 1
    return found


def poutine(root):
    run = _execute(["poutine", "analyze_local", ".", "-f", "json", "--quiet", "--disable-version-check"], {0},
                   cwd=root)
    if "{" not in run.stdout:
        raise ToolFailed("no JSON output")
    data = _json(run.stdout[run.stdout.index("{"):])
    return Counter((item["rule_id"], item.get("meta", {}).get("path"), item.get("meta", {}).get("job"))
                   for item in data.get("findings") or [])


def actionlint(root):
    files = sorted(str(p) for p in (root / ".github/workflows").glob("*.y*ml"))
    if not files:
        return Counter()
    # 0: no problems; 1: problems found. 2 and 3 are usage and fatal errors.
    run = _execute(["actionlint", "-no-color", "-format", "{{json .}}", *files], {0, 1}, cwd=root)
    return Counter((item["kind"], relative(item["filepath"], root), None) for item in _json(run.stdout or "[]"))


TOOLS = {"zizmor": zizmor, "poutine": poutine, "actionlint": actionlint}


def remit(base, head, slug):
    run = subprocess.run([sys.executable, "-m", "remit", "scan", "--dirs", str(base), str(head),
                          "--repository-name", slug], capture_output=True, text=True, check=False,
                         env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    if run.returncode:
        raise RuntimeError(f"remit exited {run.returncode}: {run.stderr.strip()[-300:]}")
    report = json.loads(run.stdout)
    keys = ("rule", "file", "job", "jobs", "line", "after")
    return {"analysis": report["analysis"],
            "findings": [{key: finding.get(key) for key in keys} for finding in report["findings"]],
            "diagnostics": [diagnostic["reason"] for diagnostic in report["diagnostics"]]}


def run(args):
    tools = {name: fn for name, fn in TOOLS.items() if shutil.which(name)}
    done = set()
    if args.output.exists():
        done = {json.loads(line)["commit"] for line in args.output.read_text().splitlines() if line}
    rows = [line.split("\t") for line in args.commits.read_text().splitlines()[1:]]
    with args.output.open("a") as out:
        for slug, commit, parent in rows:
            if commit in done:
                continue
            row = {"repository": slug, "commit": commit, "parent": parent}
            work = Path(tempfile.mkdtemp())
            try:
                repo = fetch(args.cache, slug, commit)
                materialize(repo, parent, work / "base")
                materialize(repo, commit, work / "head")
                start = time.monotonic()
                row["remit"] = remit(work / "base", work / "head", slug)
                row["remit"]["seconds"] = round(time.monotonic() - start, 2)
                for name, tool in tools.items():
                    try:
                        before, after = tool(work / "base"), tool(work / "head")
                    except (ToolFailed, OSError, KeyError, TypeError, IndexError) as error:
                        row[name] = {"failed": str(error) or type(error).__name__}
                        continue
                    row[name] = [[*key, count - before.get(key, 0)] for key, count in after.items()
                                 if count > before.get(key, 0)]
            except (RuntimeError, OSError, ValueError) as error:
                row["error"] = str(error)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            out.write(json.dumps(row) + "\n")
            out.flush()
            print(slug, commit[:8], row.get("remit", {}).get("analysis", "error"), flush=True)


def _ran(row, name):
    """The tool's new findings on this commit, or None when it failed on either side."""
    value = row.get(name)
    return value if isinstance(value, list) else None


def summarize(args):
    every = [json.loads(line) for line in args.results.read_text().splitlines() if line]
    rows = [r for r in every if "remit" in r]
    tools = [name for name in TOOLS if any(name in r for r in rows)]
    summary = {"commits": len(rows), "repositories": len({r["repository"] for r in rows}),
               # Commits that could not be fetched, or where Remit itself failed.
               "commitsNotRun": len(every) - len(rows),
               "remitAnalysis": dict(Counter(r["remit"]["analysis"] for r in rows)),
               # A failed run is not zero findings: those commits are left out of that tool's counts.
               "toolRunsFailed": {name: sum(1 for r in rows if name in r and _ran(r, name) is None)
                                  for name in tools},
               "commitsWithNewFindings": {}, "newFindings": {}}
    for name in ["remit", *tools]:
        if name == "remit":
            counts = [len(r["remit"]["findings"]) for r in rows]
        else:
            counts = [sum(item[-1] for item in _ran(r, name)) for r in rows if _ran(r, name) is not None]
        summary["commitsWithNewFindings"][name] = sum(1 for c in counts if c)
        summary["newFindings"][name] = sum(counts)
    overlap = defaultdict(Counter)
    compared = [name for name in tools if name != "actionlint"]
    for r in rows:
        failed = any(_ran(r, name) is None for name in compared)
        others = [item for name in compared for item in _ran(r, name) or []]
        for finding in r["remit"]["findings"]:
            jobs = {finding["job"], None} | {entry["job"] for entry in finding.get("jobs") or []}
            related = any(item[0] in RELATED[finding["rule"]] and item[1] == finding["file"]
                          and (finding["job"] is None or item[2] in jobs) for item in others)
            overlap[finding["rule"]]["findings"] += 1
            if related:
                overlap[finding["rule"]]["alsoNewInAnotherTool"] += 1
            elif failed:
                # Another tool failed on this commit, so it cannot count as Remit-only.
                overlap[finding["rule"]]["anotherToolFailed"] += 1
            else:
                overlap[finding["rule"]]["remitOnly"] += 1
    summary["remitByRule"] = {rule: dict(counts) for rule, counts in sorted(overlap.items())}
    summary["remitOnly"] = sum(counts["remitOnly"] for counts in overlap.values())
    summary["remitFindingsWhereAnotherToolFailed"] = sum(counts["anotherToolFailed"] for counts in overlap.values())
    seconds = sorted(r["remit"]["seconds"] for r in rows)
    summary["remitSeconds"] = {"median": statistics.median(seconds), "max": seconds[-1]}
    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    runner = commands.add_parser("run")
    runner.add_argument("--commits", type=Path, default=COMMITS)
    runner.add_argument("--cache", type=Path, default=ROOT / ".field-cache")
    runner.add_argument("--output", type=Path, default=ROOT / "field-results.jsonl")
    summary = commands.add_parser("summarize")
    summary.add_argument("results", type=Path)
    args = parser.parse_args()
    run(args) if args.command == "run" else summarize(args)


if __name__ == "__main__":
    main()
