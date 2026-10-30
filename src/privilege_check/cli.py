import argparse
import json
from pathlib import Path
import sys

from .report import markdown
from .scan import LIMITATIONS, compare, permissions
from .sources import InputError, directory, git_snapshot


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="workflow-privilege-check")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Report supported changes without executing workflow code")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--dirs", nargs=2, metavar=("BASE_DIR", "HEAD_DIR"))
    source.add_argument("--repo", help="Local Git repository; reads objects without checkout")
    scan.add_argument("--base", help="Base ref, resolved and recorded as an exact commit")
    scan.add_argument("--head", help="Head ref, resolved and recorded as an exact commit")
    scan.add_argument("--default-permissions", help='Trusted explicit JSON map, for example {"contents":"read"}')
    scan.add_argument("--format", choices=("json", "markdown"), default="json")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--summary", type=Path, help="Explicit path to append a Markdown job summary")
    args = parser.parse_args(argv)
    if args.repo and (not args.base or not args.head):
        parser.error("--repo requires --base and --head")
    if args.dirs and (args.base or args.head):
        parser.error("--base and --head are only used with --repo")
    try:
        defaults = None
        if args.default_permissions is not None:
            try:
                defaults = json.loads(args.default_permissions)
                if not isinstance(defaults, dict):
                    raise ValueError("Explicit map required")
                defaults = permissions(defaults)
            except (ValueError, TypeError) as exc:
                raise InputError("Default permissions must be a supported explicit JSON permission map.") from exc
        if args.dirs:
            base, head = (directory(path) for path in args.dirs)
        else:
            base = git_snapshot(args.repo, args.base)
            head = git_snapshot(args.repo, args.head)
        result = compare(base, head, defaults)
    except (InputError, OSError) as exc:
        # Do not echo filesystem errors, source text, credentials, or git stderr.
        reason = str(exc) if isinstance(exc, InputError) else "Could not read comparison inputs."
        result = {"schemaVersion": "0.1", "base": None, "head": None, "analysis": "error",
                  "review": "none", "findings": [], "diagnostics": [{"file": "input", "job": None,
                  "side": "comparison", "kind": "error", "reason": reason}], "limitations": LIMITATIONS.copy()}
    text = json.dumps(result, indent=2, sort_keys=True) + "\n" if args.format == "json" else markdown(result)
    try:
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as handle:
                handle.write(markdown(result))
    except OSError:
        print("Could not write report output.", file=sys.stderr)
        return 2
    return 0 if result["analysis"] == "complete" else 2
