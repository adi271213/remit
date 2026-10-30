"""Run the local suite and retain machine-readable evidence."""
from pathlib import Path
import hashlib
import json
import sys
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"test": test.id(), "outcome": "passed"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append({"test": test.id(), "outcome": "failed"})

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append({"test": test.id(), "outcome": "error"})


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    evidence = {"python": sys.version.split()[0], "pyyaml": yaml.__version__,
                "testsRun": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                "results": result.records,
                "scope": "Local synthetic acceptance and Git/Action-entry integration tests. No hosted Actions run or real-PR benchmark.",
                "sourceHashes": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for folder in ("src", "scripts", "tests") for p in sorted((ROOT/folder).rglob("*"))
                    if p.suffix in (".py", ".sh", ".json") and p.name != "validation-results.json"}}
    for filename in ("action.yml", "requirements.txt", "pyproject.toml"):
        evidence["sourceHashes"][filename] = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
    (ROOT / "validation-results.json").write_text(json.dumps(evidence, indent=2)+"\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
