import argparse
import json
from pathlib import Path
import sys

from .report import markdown
from .sarif import sarif
from .scan import REPOSITORY_NAME, audit, compare, error_report, permissions
from .sources import InputError, directory, git_snapshot


def _outputs(parser):
    parser.add_argument("--default-permissions", help='Trusted explicit JSON map, for example {"contents":"read"}')
    parser.add_argument("--format", choices=("json", "markdown", "sarif"), default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path, help="Explicit path to append a Markdown job summary")
    parser.add_argument("--sarif", type=Path, help="Also write a SARIF 2.1.0 report to this path")
    parser.add_argument("--repository-name", metavar="OWNER/REPO",
                        help="The analysed repository, so references to it by full name count as its own code")


def _defaults(value):
    if value is None:
        return None
    try:
        defaults = json.loads(value)
        if not isinstance(defaults, dict):
            raise ValueError("Explicit map required")
        return permissions(defaults)
    except (ValueError, TypeError) as exc:
        raise InputError("Default permissions must be a supported explicit JSON permission map.") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="remit")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Report what a change does to workflow privileges")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--dirs", nargs=2, metavar=("BASE_DIR", "HEAD_DIR"))
    source.add_argument("--repo", help="Local Git repository; reads objects without checkout")
    scan.add_argument("--base", help="Base ref, resolved and recorded as an exact commit")
    scan.add_argument("--head", help="Head ref, resolved and recorded as an exact commit")
    _outputs(scan)

    check = commands.add_parser("audit", help="Report pull request content reachable from privileged workflows now "
                                              "(WF010, WF011)")
    target = check.add_mutually_exclusive_group(required=True)
    target.add_argument("--dir", help="Directory containing .github/workflows")
    target.add_argument("--repo", help="Local Git repository; reads objects without checkout")
    check.add_argument("--ref", help="Commit or ref to audit with --repo (default: HEAD)")
    check.add_argument("--fail-on-findings", action="store_true",
                       help="Exit 1 when the audit is complete and has findings")
    _outputs(check)

    args = parser.parse_args(argv)
    if args.command == "scan":
        if args.repo and (not args.base or not args.head):
            parser.error("--repo requires --base and --head")
        if args.dirs and (args.base or args.head):
            parser.error("--base and --head are only used with --repo")
    elif args.dir and args.ref:
        parser.error("--ref is only used with --repo")

    try:
        defaults = _defaults(args.default_permissions)
        if args.repository_name is not None and not REPOSITORY_NAME.fullmatch(args.repository_name):
            raise InputError("Repository name must be owner/repo.")
        if args.command == "audit":
            snapshot = directory(args.dir) if args.dir else git_snapshot(args.repo, args.ref or "HEAD")
            result = audit(snapshot, defaults, repository=args.repository_name)
        else:
            if args.dirs:
                base, head = (directory(path) for path in args.dirs)
            else:
                base = git_snapshot(args.repo, args.base)
                head = git_snapshot(args.repo, args.head)
            result = compare(base, head, defaults, repository=args.repository_name)
    except (InputError, OSError, RecursionError) as exc:
        # Do not echo filesystem errors, source text, credentials, or git stderr.
        reason = str(exc) if isinstance(exc, InputError) else "Could not read comparison inputs."
        if isinstance(exc, RecursionError):
            # Every known deep structure is bounded where it is read; this keeps anything missed
            # from ending the run without a report.
            reason = "An input nests too deeply to analyze."
        result = error_report(reason)
        if args.command == "audit":
            result["mode"] = "audit"

    if args.format == "markdown":
        text = markdown(result)
    else:
        text = json.dumps(sarif(result) if args.format == "sarif" else result, indent=2, sort_keys=True) + "\n"
    try:
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        if args.sarif:
            args.sarif.write_text(json.dumps(sarif(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as handle:
                handle.write(markdown(result))
    except OSError:
        print("Could not write report output.", file=sys.stderr)
        return 2
    if result["analysis"] != "complete":
        return 2
    return 1 if args.command == "audit" and args.fail_on_findings and result["findings"] else 0
