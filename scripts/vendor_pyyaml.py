"""Reproduce the dependency bundle from its reviewed wheel URL and digest."""
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_WHEEL_BYTES = 4 * 1024 * 1024


def refresh(root=ROOT):
    destination = root / "vendor/pyyaml"
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    url = manifest["sourceURL"]
    source = urllib.parse.urlsplit(url)
    if (manifest["name"] != "PyYAML" or source.scheme != "https"
            or source.netloc != "files.pythonhosted.org"
            or source.query or source.fragment
            or Path(source.path).name != manifest["sourceWheel"]
            or not manifest["sourceWheel"].endswith(".whl")
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["sourceSha256"])):
        raise ValueError("Invalid reviewed wheel pin in vendor/pyyaml/manifest.json.")
    with urllib.request.urlopen(url, timeout=30) as response:
        blob = response.read(MAX_WHEEL_BYTES + 1)
        # urlopen follows redirects. Require the reviewed artifact URL as well.
        if response.geturl() != url:
            raise ValueError("The reviewed wheel URL redirected; review the pin before retrying.")
    if len(blob) > MAX_WHEEL_BYTES or hashlib.sha256(blob).hexdigest() != manifest["sourceSha256"]:
        raise ValueError("Wheel size/hash mismatch; the existing bundle was not changed.")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        members = archive.namelist()
        files = [name for name in members if name.startswith("yaml/")
                 and name.endswith(".py") and len(Path(name).parts) == 2]
        licenses = [name for name in members if name.endswith(".dist-info/licenses/LICENSE")]
        if len(files) < 15 or len(files) != len(set(files)) or len(licenses) != 1:
            raise ValueError("Unexpected wheel layout; the existing bundle was not changed.")
        # Validate all content before touching the checked-in dependency.
        content = {name: archive.read(name) for name in files}
        content["LICENSE"] = archive.read(licenses[0])
    actual = {p.relative_to(destination).as_posix() for p in destination.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts and p.name != "manifest.json"}
    if actual - content.keys():
        raise ValueError("Unexpected existing vendor files; review removals explicitly.")
    for name in content:
        path = destination / name
        if path.is_symlink() or not path.resolve().is_relative_to(destination.resolve()):
            raise ValueError("Invalid destination path; the existing bundle was not changed.")
    for name, data in content.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(content.items())}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Verified reviewed wheel; bundled {len(files)} Python files and license; no compiled binaries.")


if __name__ == "__main__":
    try:
        refresh()
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"Dependency refresh failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
