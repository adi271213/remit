# Bundled Action dependency

The Action uses the unmodified pure-Python files of PyYAML 6.0.3 in `pyyaml/`.
Its MIT license and per-file SHA-256 manifest are included. The manifest records
the published upstream wheel URL and verified SHA-256. The optional compiled
extension is omitted; the scanner already uses Python SafeLoader subclasses.

The pinned Action verifies these files before starting the isolated scanner. It
creates no venv and invokes no pip, dependency index, installer or download.
Python 3.11+ and Git must exist on the runner. Downloading the Action and fetching
Git objects are installation operations and can still require network access.

To reproduce the current bundle, run `python scripts/vendor_pyyaml.py`. It fetches
only the wheel URL recorded in `pyyaml/manifest.json` and checks the recorded
SHA-256 before writing files. It does not select a release or trust a new checksum
from live package metadata.

For an update, review the upstream release and wheel digest, then change the
manifest's `version`, `sourceWheel`, `sourceURL` and `sourceSha256` together. Update
the runtime's expected dependency version, package/test dependencies and their
hash pins. Regenerate the bundle and review the resulting files, license and
manifest. Run the full Python matrix and disconnected-network smoke test before
publishing. Never copy a newly downloaded checksum into the manifest merely to
make verification pass.
