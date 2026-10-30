"""Create local Git inputs for the hosted contract; never execute fixture code."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def create(case, parent):
    fixture = json.loads((ROOT / "tests/hosted_cases.json").read_text())[case]
    repo = Path(tempfile.mkdtemp(prefix="wpc-contract-", dir=parent))

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                       stderr=subprocess.DEVNULL).strip()

    git("init", "-q", "-b", "main")
    git("config", "user.name", "Contract fixture")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "commit.gpgsign", "false")
    path = repo / ".github/workflows/ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(fixture["base"], encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    path.write_text(fixture["head"], encoding="utf-8")
    git("add", ".")
    git("commit", "--allow-empty", "-qm", "head")
    head = git("rev-parse", "HEAD")
    mutation = fixture.get("mutation")
    if mutation == "missing":
        head = "0" * 40
    elif mutation == "replace-commit":
        git("replace", head, base)
    elif mutation == "replace-blob":
        git("replace", git("rev-parse", head + ":.github/workflows/ci.yml"),
            git("rev-parse", base + ":.github/workflows/ci.yml"))
    return {"base": base, "head": head, "repo": str(repo)}


if __name__ == "__main__":
    values = create(sys.argv[1], os.environ["RUNNER_TEMP"])
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
        # Paths are runner-controlled; multiline outputs also preserve spaces.
        import uuid
        for key, value in values.items():
            delimiter = "wpc_" + uuid.uuid4().hex
            handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
