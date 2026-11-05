"""Plant known privilege changes into real workflows and check that Remit reports them.

Each operator takes a real job, applies one change, and compares the workflow before and
after (both written with the same serializer, so the planted change is the only difference).
Privilege operators must be reported with the expected rule; benign operators must not be.
Setup that an operator needs (a privileged trigger, a secret that makes the job privileged)
is applied to both sides.

    python scripts/planted_changes.py corpus --repos benchmarks/heldout/planted-corpus.tsv --output corpus.json
    python scripts/planted_changes.py run corpus.json --output planted.jsonl
    python scripts/planted_changes.py summarize planted.jsonl

The operators are the patterns Remit is designed to catch, so this measures how reliably it
catches them across real workflow shapes, not how it does on patterns nobody anticipated.
"""
import argparse
from collections import Counter, defaultdict
import copy
import json
from pathlib import Path
import random
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import yaml  # noqa: E402
from remit.scan import compare, load_yaml  # noqa: E402
from remit.sources import Snapshot  # noqa: E402

corpus = {}
PLANTED_ACTION = "planted-owner/planted-action@v1"
# A job that already brings in pull request content: a second fetch is not a change.
ALREADY_FETCHES = re.compile(r"pull_request\.head\.|head_ref|workflow_run\.(id|head_)|refs/pull|pull/\$"
                             r"|gh pr (checkout|diff)|download-artifact")
PR = {"pull_request_target": {"types": ["opened", "synchronize"]}}
WR = {"workflow_run": {"workflows": ["CI"], "types": ["completed"]}}
HOSTED = {"ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04", "windows-latest", "macos-latest", "macos-14", "macos-15"}


def dump(doc):
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=4096)


def triggers(doc):
    on = doc.get("on")
    return {on} if isinstance(on, str) else set(on) if isinstance(on, (list, dict)) else set()


def steps_jobs(doc):
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return []
    return [n for n, j in jobs.items() if isinstance(j, dict) and isinstance(j.get("steps"), list) and j["steps"]
            and all(isinstance(s, dict) for s in j["steps"]) and "uses" not in j]


def effective_perms(doc, job):
    p = job.get("permissions", doc.get("permissions"))
    return p if isinstance(p, dict) else None


def privileged(doc, job):
    p = job.get("permissions", doc.get("permissions"))
    text = json.dumps(job).replace("secrets.GITHUB_TOKEN", "")
    return (p == "write-all" or (isinstance(p, dict) and "write" in p.values())) or "secrets." in text \
        or bool(job.get("environment"))


def make_privileged(doc, job):
    if not privileged(doc, job):
        job.setdefault("env", {}) if isinstance(job.get("env", {}), dict) else None
        if isinstance(job.get("env"), dict):
            job["env"]["PLANTED_TOKEN"] = "${{ secrets.PLANTED_TOKEN }}"
            return True
        return False
    return True


def insert_step(job, step, rng):
    job["steps"].insert(rng.randint(0, len(job["steps"])), step)


# Each operator: (kind, expected rules, function(doc, name, rng, files) -> (setup_doc, mutated_doc, extra) or None)
# setup_doc is applied to both sides; extra may carry action files {path: (base_text, head_text)}.
def op_write(doc, name, rng, files):
    job = doc["jobs"][name]
    p = effective_perms(doc, job)
    if p is None or any(not isinstance(v, str) for v in p.values()):
        return None
    candidates = ("contents", "pull-requests", "issues", "packages", "actions", "deployments", "statuses", "checks")
    scopes = [s for s in candidates
              if p.get(s) != "write"]
    if not scopes:
        return None
    head = copy.deepcopy(doc)
    head["jobs"][name]["permissions"] = {**p, rng.choice(scopes): "write"}
    return doc, head, {}


def op_oidc(doc, name, rng, files):
    job = doc["jobs"][name]
    p = effective_perms(doc, job)
    if p is None or p.get("id-token") == "write" or any(not isinstance(v, str) for v in p.values()):
        return None
    head = copy.deepcopy(doc)
    head["jobs"][name]["permissions"] = {**p, "id-token": "write"}
    return doc, head, {}


def op_drop_perms(doc, name, rng, files):
    job = doc["jobs"][name]
    if not isinstance(job.get("permissions"), dict) or "permissions" in doc:
        return None
    head = copy.deepcopy(doc)
    del head["jobs"][name]["permissions"]
    return doc, head, {}


def op_trigger(doc, name, rng, files):
    if "pull_request_target" in triggers(doc):
        return None
    head = copy.deepcopy(doc)
    on = head.get("on")
    if isinstance(on, dict):
        on["pull_request_target"] = None
    else:
        head["on"] = sorted(triggers(doc) | {"pull_request_target"})
    return doc, head, {}


def op_secret(doc, name, rng, files):
    head = copy.deepcopy(doc)
    step = rng.choice(head["jobs"][name]["steps"])
    env = step.setdefault("env", {})
    if not isinstance(env, dict):
        return None
    env["PLANTED"] = "${{ secrets.PLANTED_SECRET }}"
    return doc, head, {}


def op_self_hosted(doc, name, rng, files):
    if doc["jobs"][name].get("runs-on") not in HOSTED:
        return None
    head = copy.deepcopy(doc)
    head["jobs"][name]["runs-on"] = ["self-hosted", "linux"]
    return doc, head, {}


def op_environment(doc, name, rng, files):
    if "environment" in doc["jobs"][name]:
        return None
    head = copy.deepcopy(doc)
    head["jobs"][name]["environment"] = "planted-production"
    return doc, head, {}


def op_action(doc, name, rng, files):
    base = copy.deepcopy(doc)
    if not make_privileged(base, base["jobs"][name]):
        return None
    head = copy.deepcopy(base)
    insert_step(head["jobs"][name], {"uses": PLANTED_ACTION}, rng)
    return base, head, {}


def op_action_in_composite(doc, name, rng, files):
    for step in doc["jobs"][name]["steps"]:
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("./") and "@" not in uses:
            path = uses[2:].strip("/")
            for candidate in (f"{path}/action.yml", f"{path}/action.yaml"):
                text = files.get(candidate)
                if text is None:
                    continue
                try:
                    action = load_yaml(text)[0]
                except Exception:
                    return None
                runs = action.get("runs") if isinstance(action, dict) else None
                composite = isinstance(runs, dict) and runs.get("using") == "composite"
                if not (composite and isinstance(runs.get("steps"), list)):
                    return None
                base = copy.deepcopy(doc)
                if not make_privileged(base, base["jobs"][name]):
                    return None
                planted = copy.deepcopy(action)
                planted["runs"]["steps"].append({"uses": PLANTED_ACTION})
                return base, copy.deepcopy(base), {candidate: (dump(action), dump(planted))}
    return None


def pwn(step_or_steps, on=PR, job_env=None, actions=None):
    def op(doc, name, rng, files):
        if ALREADY_FETCHES.search(json.dumps(doc["jobs"][name])):
            return None  # the job already brings in pull request content; a second fetch is not a change
        base = copy.deepcopy(doc)
        base["on"] = copy.deepcopy(on)
        # Setup on both sides: conditions on the job, or on jobs it needs, may only allow other
        # events (push, pull_request), which would make the planted step unreachable.
        pending, seen = [name], set()
        while pending:
            current = pending.pop()
            target = base["jobs"].get(current)
            if current in seen or not isinstance(target, dict):
                continue
            seen.add(current)
            target.pop("if", None)
            needs = target.get("needs")
            pending.extend([needs] if isinstance(needs, str) else needs if isinstance(needs, list) else [])
        head = copy.deepcopy(base)
        job = head["jobs"][name]
        if job_env:
            if not isinstance(job.get("env", {}), dict):
                return None
            job.setdefault("env", {}).update(job_env)
        position = rng.randint(0, len(job["steps"]))
        for offset, step in enumerate(step_or_steps):
            job["steps"].insert(position + offset, copy.deepcopy(step))
        extra = {path: (text, text) for path, text in (actions or {}).items()}
        return base, head, extra
    return op


CHECKOUT = "actions/checkout@v4"
FETCH_ACTION = ("name: planted fetch\ninputs:\n  ref:\n    required: true\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@v4\n      with:\n        ref: ${{ inputs.ref }}\n")
PWN = {
    "pwn: checkout head.ref": pwn([{"uses": CHECKOUT, "with": {"ref": "${{ github.event.pull_request.head.ref }}"}}]),
    "pwn: checkout head.sha": pwn([{"uses": CHECKOUT, "with": {"ref": "${{ github.event.pull_request.head.sha }}"}}]),
    "pwn: checkout github.head_ref": pwn([{"uses": CHECKOUT, "with": {"ref": "${{ github.head_ref }}"}}]),
    "pwn: via env variable": pwn([{"run": 'git fetch origin "$PLANTED_REF" && git checkout "$PLANTED_REF"'}],
                                  job_env={"PLANTED_REF": "${{ github.event.pull_request.head.sha }}"}),
    "pwn: via step output": pwn([{"id": "planted",
                                  "run": 'echo "ref=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_OUTPUT"'},
                                 {"uses": CHECKOUT, "with": {"ref": "${{ steps.planted.outputs.ref }}"}}]),
    "pwn: gh pr checkout": pwn([{"run": "gh pr checkout ${{ github.event.pull_request.number }}"}]),
    "pwn: git fetch refs/pull": pwn([{"run": "git fetch origin pull/${{ github.event.pull_request.number }}/head:pr"
                                             " && git checkout pr"}]),
    "pwn: gh pr diff | git apply": pwn([{"run": "gh pr diff ${{ github.event.pull_request.number }} | git apply"}]),
    "pwn: workflow_run artifact": pwn([{"uses": "actions/download-artifact@v4",
                                        "with": {"run-id": "${{ github.event.workflow_run.id }}",
                                                 "github-token": "${{ github.token }}"}}],
                                       on=WR),
    "pwn: composite action input": pwn([{"uses": "./.github/actions/planted-fetch",
                                         "with": {"ref": "${{ github.event.pull_request.head.ref }}"}}],
                                       actions={".github/actions/planted-fetch/action.yml": FETCH_ACTION}),
}


def benign_rename(doc, name, rng, files):
    head = copy.deepcopy(doc)
    rng.choice(head["jobs"][name]["steps"])["name"] = "Renamed by the planted-change test"
    return doc, head, {}


def benign_bump(doc, name, rng, files):
    head = copy.deepcopy(doc)
    steps = [s for s in head["jobs"][name]["steps"] if isinstance(s.get("uses"), str) and "@" in s["uses"]
             and not s["uses"].startswith(("./", "$/", "docker://", "actions/", "github/"))]
    if not steps:
        return None
    step = rng.choice(steps)
    step["uses"] = step["uses"].split("@")[0] + "@v999"
    return doc, head, {}


def benign_readonly_job(doc, name, rng, files):
    if "planted-readonly" in doc["jobs"] or "secrets." in json.dumps(doc.get("env")):
        return None
    head = copy.deepcopy(doc)
    head["jobs"]["planted-readonly"] = {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                                        "steps": [{"run": "echo hello"}]}
    return doc, head, {}


def benign_ubuntu(doc, name, rng, files):
    if doc["jobs"][name].get("runs-on") not in ("ubuntu-22.04", "ubuntu-latest"):
        return None
    head = copy.deepcopy(doc)
    head["jobs"][name]["runs-on"] = "ubuntu-24.04"
    return doc, head, {}


BENIGN = {
    "benign: renamed step": (benign_rename, "none"),
    "benign: action version bump": (benign_bump, "none"),
    "benign: new read-only job": (benign_readonly_job, "none"),
    "benign: ubuntu-22.04 -> 24.04": (benign_ubuntu, "none"),
    "benign: pull_request_target checkout of github.sha":
        (pwn([{"uses": CHECKOUT, "with": {"ref": "${{ github.sha }}"}}]), "pwn"),
    "benign: workflow_run checkout gated to push":
        (lambda doc, name, rng, files: gated(doc, name, rng, files), "pwn"),
}


def gated(doc, name, rng, files):
    checkout = {"uses": CHECKOUT, "with": {"ref": "${{ github.event.workflow_run.head_sha }}"}}
    made = pwn([checkout], on=WR)(doc, name, rng, files)
    if made is None:
        return None
    for side in made[:2]:
        side["jobs"][name]["if"] = "github.event.workflow_run.event == 'push'"
    return made


OPERATORS = {
    "new write scope": (op_write, {"WF001"}), "new id-token: write": (op_oidc, {"WF001"}),
    "permissions block removed": (op_drop_perms, {"WF002"}), "new pull_request_target trigger": (op_trigger, {"WF003"}),
    "new secret": (op_secret, {"WF004"}), "self-hosted runner": (op_self_hosted, {"WF005"}),
    "new environment": (op_environment, {"WF007"}), "third-party action, privileged job": (op_action, {"WF009"}),
    "third-party action inside local composite": (op_action_in_composite, {"WF009"}),
    **{k: (v, {"WF010", "WF011"}) for k, v in PWN.items()},
}



def build_corpus(args):
    from field_comparison import fetch  # noqa: E402
    result = {}
    for line in args.repos.read_text().splitlines()[1:]:
        slug, commit = line.split("\t")
        repo = fetch(args.cache, slug, commit)
        names = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", commit],
                               capture_output=True, text=True, check=True).stdout.splitlines()
        files = {}
        for name in names:
            workflow = (name.startswith(".github/workflows/") and name.count("/") == 2
                        and name.endswith((".yml", ".yaml")))
            if workflow or name.rsplit("/", 1)[-1] in ("action.yml", "action.yaml"):
                blob = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{name}"], capture_output=True)
                if blob.returncode == 0:
                    try:
                        files[name] = blob.stdout.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
        result[slug] = files
        print(slug, len(files), flush=True)
    args.output.write_text(json.dumps(result))


def run_case(repo, path, made):
    base_doc, head_doc, extra = made
    base_files = dict(corpus[repo])
    head_files = dict(base_files)
    base_files[path], head_files[path] = dump(base_doc), dump(head_doc)
    for p, (b, h) in extra.items():
        base_files[p], head_files[p] = b, h

    def workflows(files):
        return {k: v for k, v in files.items() if k.startswith(".github/workflows/")}
    return compare(Snapshot("b", workflows(base_files), base_files.get),
                   Snapshot("h", workflows(head_files), head_files.get), repository=repo)


def matches(finding, expected, path, name, extra):
    """A detection counts only for the planted change itself: the expected rule, on the
    workflow or an action file the operator planted, for the planted workflow and job."""
    if finding["rule"] not in expected or finding.get("file") not in {path, *extra}:
        return False
    places = {(entry.get("workflow"), entry.get("job")) for entry in finding.get("jobs") or []}
    # "workflow" is set only when the finding sits in another file (an action or reusable workflow).
    places.add((finding.get("workflow", finding.get("file")), finding.get("job")))
    if finding["rule"] == "WF003":  # a trigger belongs to the workflow, not a job
        return any(workflow == path for workflow, _ in places)
    return (path, name) in places


def run(args):
    corpus.update(json.loads(args.corpus.read_text()))
    sites = []
    for repo, files in sorted(corpus.items()):
        for path, text in sorted(files.items()):
            if not path.startswith(".github/workflows/"):
                continue
            try:
                doc = load_yaml(text)[0]
            except Exception:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("jobs"), dict) and "on" in doc:
                sites.extend((repo, path, name) for name in steps_jobs(doc))
    operators = {**OPERATORS, **BENIGN}
    with args.output.open("w") as out:
        for label, (fn, expected) in operators.items():
            rng = random.Random(f"{args.seed}:{label}")
            order = sites[:]
            rng.shuffle(order)
            done = 0
            for repo, path, name in order:
                if done >= args.sites:
                    break
                # A JSON round trip un-shares YAML aliases, so a change to one job's steps can't
                # silently appear in every job that reuses the same anchored list.
                doc = json.loads(json.dumps(load_yaml(corpus[repo][path])[0]))
                try:
                    made = fn(doc, name, rng, corpus[repo])
                except (KeyError, TypeError, AttributeError, IndexError):
                    made = None
                if made is None:
                    continue
                done += 1
                report = run_case(repo, path, made)
                found = [(f["rule"], f["job"], [j["job"] for j in f.get("jobs") or []]) for f in report["findings"]]
                if isinstance(expected, set):
                    hit = any(matches(f, expected, path, name, made[2]) for f in report["findings"])
                    outcome = "detected" if hit else "missed"
                elif expected == "none":
                    outcome = "quiet" if not found else "false alarm"
                else:
                    outcome = "false alarm" if any(rule in ("WF010", "WF011") for rule, *_ in found) else "quiet"
                out.write(json.dumps({"operator": label, "repository": repo, "file": path, "job": name,
                                      "outcome": outcome, "analysis": report["analysis"], "rules": found[:8]}) + "\n")
            print(label, done, flush=True)


def summarize(args):
    counts, incomplete = defaultdict(Counter), Counter()
    for line in args.results.read_text().splitlines():
        row = json.loads(line)
        counts[row["operator"]][row["outcome"]] += 1
        incomplete[row["operator"]] += row["analysis"] != "complete"
    for operator, outcome in counts.items():
        total = sum(outcome.values())
        good = outcome["detected"] + outcome["quiet"]
        print(f"{operator:52} {good:4}/{total:<4} {100 * good / total:6.1f}%  incomplete: {incomplete[operator]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("corpus")
    build.add_argument("--repos", type=Path, default=ROOT / "benchmarks/heldout/planted-corpus.tsv")
    build.add_argument("--cache", type=Path, default=ROOT / ".field-cache")
    build.add_argument("--output", type=Path, required=True)
    runner = commands.add_parser("run")
    runner.add_argument("corpus", type=Path)
    runner.add_argument("--output", type=Path, required=True)
    runner.add_argument("--seed", type=int, default=2026)
    runner.add_argument("--sites", type=int, default=150, help="Jobs per operator")
    summary = commands.add_parser("summarize")
    summary.add_argument("results", type=Path)
    args = parser.parse_args()
    {"corpus": build_corpus, "run": run, "summarize": summarize}[args.command](args)


if __name__ == "__main__":
    main()
