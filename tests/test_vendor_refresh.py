"""Maintenance downloads must obey the checked-in source pin, not live metadata."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vendor_refresh", ROOT / "scripts/vendor_pyyaml.py")
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)


class Response(io.BytesIO):
    def geturl(self):
        return "https://files.pythonhosted.org/packages/test.whl"


class VendorRefresh(unittest.TestCase):
    def fixture(self, root):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as wheel:
            for index in range(15):
                wheel.writestr(f"yaml/module{index}.py", f"# fixture {index}\n")
            wheel.writestr("pyyaml.dist-info/licenses/LICENSE", "fixture license")
        blob = buffer.getvalue()
        folder = root / "vendor/pyyaml"
        folder.mkdir(parents=True)
        manifest = {"name": "PyYAML", "version": "fixture", "sourceWheel": "test.whl",
                    "sourceURL": Response(b"").geturl(),
                    "sourceSha256": hashlib.sha256(blob).hexdigest(), "files": {}}
        (folder / "manifest.json").write_text(json.dumps(manifest))
        return folder, manifest, blob

    def test_refresh_uses_exact_recorded_url_and_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            folder, manifest, blob = self.fixture(Path(temp))
            with patch.object(vendor.urllib.request, "urlopen", return_value=Response(blob)) as download:
                vendor.refresh(Path(temp))
            download.assert_called_once_with(manifest["sourceURL"], timeout=30)
            result = json.loads((folder / "manifest.json").read_text())
            self.assertEqual(result["sourceSha256"], manifest["sourceSha256"])
            self.assertEqual(len(result["files"]), 16)
            for name, digest in result["files"].items():
                self.assertEqual(hashlib.sha256((folder / name).read_bytes()).hexdigest(), digest)

    def test_hash_mismatch_and_redirect_leave_existing_bundle_intact(self):
        for kind in ("digest", "redirect"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                folder, _, blob = self.fixture(Path(temp))
                (folder / "LICENSE").write_text("existing")
                before = {p.name: p.read_bytes() for p in folder.iterdir()}
                response = Response(blob if kind == "redirect" else blob + b"altered")
                if kind == "redirect":
                    response.geturl = lambda: "https://example.invalid/test.whl"
                with patch.object(vendor.urllib.request, "urlopen", return_value=response), self.assertRaises(ValueError):
                    vendor.refresh(Path(temp))
                self.assertEqual({p.name: p.read_bytes() for p in folder.iterdir()}, before)

    def test_unreviewed_host_is_rejected_before_network_access(self):
        with tempfile.TemporaryDirectory() as temp:
            folder, manifest, _ = self.fixture(Path(temp))
            manifest["sourceURL"] = "https://example.invalid/test.whl"
            (folder / "manifest.json").write_text(json.dumps(manifest))
            with patch.object(vendor.urllib.request, "urlopen") as download, self.assertRaises(ValueError):
                vendor.refresh(Path(temp))
            download.assert_not_called()
