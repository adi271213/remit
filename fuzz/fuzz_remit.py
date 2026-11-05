"""Coverage-guided fuzzing of compare() and audit() with Atheris.

Each input is split into a base workflow, a head workflow and a local composite action, and
both entry points must return a report whose analysis agrees with its diagnostics, that
serializes to JSON, and that is the same when the input is analysed twice. Anything else,
including an exception, is a crash.

    pip install --require-hashes -r requirements-fuzz.txt
    python fuzz/fuzz_remit.py -max_total_time=300 fuzz/corpus

CI runs it on every pull request (see .github/workflows/fuzz.yml).
"""
import json
from pathlib import Path
import sys

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
with atheris.instrument_imports():
    from remit.scan import audit, compare
    from remit.sources import Snapshot

WORKFLOW = ".github/workflows/ci.yml"
ACTION = ".github/actions/setup/action.yml"


def snapshot(name, files):
    workflows = {k: v for k, v in files.items() if k.startswith(".github/workflows/")}
    return Snapshot(name, workflows, files.get)


def consistent(report):
    kinds = {d["kind"] for d in report["diagnostics"]}
    expected = "error" if "error" in kinds else "incomplete" if kinds else "complete"
    return report["analysis"] == expected and report["review"] == ("suggested" if report["findings"] else "none")


def test_one_input(data):
    provider = atheris.FuzzedDataProvider(data)
    base = provider.ConsumeUnicodeNoSurrogates(provider.ConsumeIntInRange(0, 4096))
    action = provider.ConsumeUnicodeNoSurrogates(provider.ConsumeIntInRange(0, 2048))
    head = provider.ConsumeUnicodeNoSurrogates(provider.remaining_bytes())
    base_files = {WORKFLOW: base, ACTION: action}
    head_files = {WORKFLOW: head, ACTION: action}
    for run in (lambda: compare(snapshot("b", base_files), snapshot("h", head_files)),
                lambda: audit(snapshot("h", head_files))):
        report = run()
        text = json.dumps(report, sort_keys=True)
        if not consistent(report):
            raise AssertionError(f"analysis {report['analysis']} disagrees with {report['diagnostics'][:2]}")
        if json.dumps(run(), sort_keys=True) != text:
            raise AssertionError("same input, different report")


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
