"""Fuzz compare() and audit() with mutations of real workflows.

Each input is a real workflow (and sometimes a local action) mutated structurally (deleted
keys, swapped types, hostile values, deep nesting) or textually (aliases, merge keys,
duplicate keys, truncation, odd characters). A failure is an exception, a report whose
analysis disagrees with its diagnostics, output that differs between two runs of the same
input, or more than 30 s of CPU for one call.

    python scripts/planted_changes.py corpus --repos benchmarks/field/fuzz-corpus.tsv --output fuzz-corpus.json
    python scripts/fuzz_workflows.py fuzz-corpus.json --iterations 5000 --seed 21
"""
import argparse
import copy
import json
from pathlib import Path
import random
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import yaml  # noqa: E402
from remit.scan import audit, compare, load_yaml  # noqa: E402
from remit.sources import Snapshot  # noqa: E402

rng = random.Random()

ODD = [None, True, False, 0, -1, 3.5, "", " ", "\t", "‮\u0000x", "é" * 50, "x" * 200_000, [], {}, [[[]]],
       {"a": {"b": {"c": None}}}, "${{", "}}", "${{ }}", "${{ github.event.pull_request.head.ref }}",
       "${{ secrets.X }}", "${{ toJSON(secrets) }}", "./", "./../../etc", "$/", "$/../x", "./.github/actions/a",
       "./.github/workflows/ci.yml", "docker://x", "a/b@", "@", "owner/repo/path@" + "f" * 40, "write-all",
       "read-all", {"contents": "admin"}, {"unknown-scope": "write"}, {"id-token": "write"}, "self-hosted",
       {"group": None}, {"labels": [None]}, "pull_request_target", ["workflow_run", "issue_comment"],
       {"workflow_run": {"workflows": None}}, "github.event.workflow_run.event == 'push' ((", "always() &&",
       "!" * 500, "(" * 300, 10 ** 400 if False else 99999999999999999999]


def nodes(value, path=()):
    yield path, value
    if isinstance(value, dict):
        for k, v in list(value.items()):
            yield from nodes(v, path + (k,))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from nodes(v, path + (i,))


def setat(root, path, new):
    if not path:
        return new
    target = root
    for p in path[:-1]:
        target = target[p]
    target[path[-1]] = new
    return root


def deep(n):
    v = "x"
    for _ in range(n):
        v = {"k": v} if rng.random() < .5 else [v]
    return v


def structural(doc):
    doc = copy.deepcopy(doc)
    for _ in range(rng.randint(1, 4)):
        spots = list(nodes(doc))
        path, value = rng.choice(spots)
        op = rng.random()
        if op < .25 and path:
            parent = doc
            for p in path[:-1]:
                parent = parent[p]
            if isinstance(parent, dict):
                parent.pop(path[-1], None)
            elif isinstance(parent, list) and len(parent) > path[-1]:
                parent.pop(path[-1])
        elif op < .55:
            doc = setat(doc, path, copy.deepcopy(rng.choice(ODD)))
        elif op < .65:
            doc = setat(doc, path, deep(rng.randint(10, 60)))
        elif op < .8:
            other = copy.deepcopy(rng.choice(spots)[1])
            doc = setat(doc, path, other)
        elif isinstance(value, dict):
            key = rng.choice(["uses", "permissions", "runs-on", "environment", "if", "needs", "steps", "with",
                              "secrets", "env", "on", "jobs", "strategy", "matrix", "run", "outputs"])
            value[key] = copy.deepcopy(rng.choice(ODD))
    return doc


def textual(text):
    lines = text.splitlines(True) or [""]
    for _ in range(rng.randint(1, 5)):
        op = rng.random()
        i = rng.randrange(len(lines))
        if op < .15:
            lines.insert(i, lines[i])                      # duplicate key/line
        elif op < .3:
            lines[i] = lines[i].replace(":", ": &a", 1) + "  extra: *a\n"
        elif op < .4:
            lines.insert(i, "<<: {x: 1}\n")
        elif op < .5:
            del lines[i:]
            lines = lines or [""]                          # truncate
        elif op < .6:
            lines[i] = lines[i].replace("  ", "\t", 1)
        elif op < .7:
            s = list(lines[i])
            if s:
                s[rng.randrange(len(s))] = rng.choice("\x00\x07{}[]&*!|>%@`'\"#\u2028\ufeff")
            lines[i] = "".join(s)
        elif op < .8:
            lines.insert(i, "a: &x [*x]\n")                 # recursive alias
        elif op < .9:
            lines[i] = " " * rng.randint(0, 40) + lines[i].lstrip()
        else:
            # Exponential alias expansion ("billion laughs").
            lines.insert(i, "".join(f"a{j}: &a{j} [" + ",".join(f"*a{j - 1}" for _ in range(9)) + "]\n"
                                    if j else "a0: &a0 [x]\n" for j in range(8)))
    return "".join(lines)


def dump(doc):
    try:
        return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=4096)
    except Exception:
        return json.dumps(doc, default=str)


def consistent(report):
    kinds = {d["kind"] for d in report["diagnostics"]}
    expected = "error" if "error" in kinds else "incomplete" if kinds else "complete"
    review = "suggested" if report["findings"] else "none"
    return report["analysis"] == expected and report["review"] == review




def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--save", type=Path, help="Directory for the head files of failing inputs")
    args = parser.parse_args()
    rng.seed(args.seed)
    corpus = json.loads(args.corpus.read_text())
    repos = [r for r, files in corpus.items() if any(k.startswith(".github/workflows/") for k in files)]
    failures, slowest, started = [], (0.0, None), time.time()

    def workflows(files):
        return {k: v for k, v in files.items() if k.startswith(".github/workflows/")}

    for n in range(args.iterations):
        repo = rng.choice(repos)
        files = corpus[repo]
        path = rng.choice([k for k in files if k.startswith(".github/workflows/")])
        base, head = dict(files), dict(files)
        try:
            doc = load_yaml(files[path])[0]
        except Exception:
            doc = None
        head[path] = dump(structural(doc)) if doc is not None and rng.random() < .6 else textual(files[path])
        if rng.random() < .3:
            actions = [k for k in files if not k.startswith(".github/workflows/")]
            if actions:
                action = rng.choice(actions)
                head[action] = textual(files[action])
        case = (repo, path, n)
        before = Snapshot("b", workflows(base), base.get)
        after = Snapshot("h", workflows(head), head.get)
        runs = (("compare", lambda b=before, h=after: compare(b, h)), ("audit", lambda h=after: audit(h)))
        for name, run in runs:
            cpu = time.process_time()
            problem = None
            try:
                report = run()
                json.dumps(report)
                if not consistent(report):
                    problem = ("inconsistent analysis", report["analysis"])
                elif n % 10 == 0 and json.dumps(run(), sort_keys=True) != json.dumps(report, sort_keys=True):
                    problem = ("non-deterministic",)
            except Exception as exc:
                problem = ("exception", type(exc).__name__, traceback.format_exc()[-600:])
            used = time.process_time() - cpu
            slowest = max(slowest, (used, case))
            if used > 30:
                problem = problem or ("slow", round(used, 1))
            if problem:
                failures.append((name, case, *problem))
                print("FAIL", json.dumps(failures[-1], default=str)[:1500], flush=True)
                if args.save:
                    target = args.save / f"{args.seed}-{n}"
                    for file, text in head.items():
                        (target / file).parent.mkdir(parents=True, exist_ok=True)
                        (target / file).write_text(text)
        if n and n % 1000 == 0:
            print(f"{n} inputs, {len(failures)} failures, {time.time() - started:.0f}s", flush=True)
    print(json.dumps({"inputs": args.iterations, "failures": len(failures), "slowestCpuSeconds": round(slowest[0], 2),
                      "slowestInput": slowest[1]}, default=str))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
