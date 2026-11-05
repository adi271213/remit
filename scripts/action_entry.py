"""Read Action metadata, then run the trusted scanner against Git objects."""
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor/pyyaml"))
from remit.cli import main
from remit.sources import merge_base


def entry():
    base = os.environ.get("PRIVILEGE_BASE", "")
    head = os.environ.get("PRIVILEGE_HEAD", "")
    base_from_event = not base
    if not base or not head:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if not event_path:
            print("Explicit base/head SHAs or a pull-request event are required.", file=sys.stderr)
            return 2
        try:
            event = json.loads(Path(event_path).read_text())
            pr = event["pull_request"]
            base = base or pr["base"]["sha"]
            head = head or pr["head"]["sha"]
        except (OSError, ValueError, KeyError, TypeError):
            print("Could not resolve comparison SHAs from the event.", file=sys.stderr)
            return 2
    full_sha = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
    if not all(isinstance(value, str) and full_sha.fullmatch(value) for value in (base, head)):
        print("The Action requires full commit SHAs.", file=sys.stderr)
        return 2
    repository = os.environ.get("PRIVILEGE_REPOSITORY", ".")
    if base_from_event:
        # The event's base SHA is the base branch's current tip. Compare from where the
        # pull request branched instead, as GitHub's Files changed view does, so changes
        # merged to the base branch since then don't appear reversed as findings.
        base = merge_base(repository, base, head) or base
    args = ["scan", "--repo", repository, "--base", base, "--head", head]
    if (name := os.environ.get("GITHUB_REPOSITORY")) and re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", name):
        args += ["--repository-name", name]
    if defaults := os.environ.get("PRIVILEGE_DEFAULTS"):
        args += ["--default-permissions", defaults]
    if output := os.environ.get("PRIVILEGE_REPORT"):
        args += ["--output", output]
    if sarif := os.environ.get("PRIVILEGE_SARIF"):
        args += ["--sarif", sarif]
    if summary := os.environ.get("PRIVILEGE_SUMMARY") or os.environ.get("GITHUB_STEP_SUMMARY"):
        args += ["--summary", summary]
    return main(args)


if __name__ == "__main__":
    raise SystemExit(entry())
