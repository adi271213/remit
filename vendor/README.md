# Bundled PyYAML

`pyyaml/` contains the unmodified pure-Python files of PyYAML 6.0.3 and its MIT
license. The optional C extension is left out. `pyyaml/manifest.json` records the
source wheel URL, its SHA-256, and a SHA-256 for each bundled file.

The Action checks every file against the manifest before starting the scanner,
so it never needs pip, a virtualenv or network access at runtime. The CLI
installed with pip uses the regular PyYAML package instead.

## Updating

1. Review the new PyYAML release and the wheel's published SHA-256.
2. In `pyyaml/manifest.json`, update `version`, `sourceWheel`, `sourceURL` and
   `sourceSha256`.
3. Run `python scripts/vendor_pyyaml.py`. It downloads only that URL, checks the
   digest, and rewrites the bundle and per-file hashes.
4. Update the expected version in `scripts/action_runner.py`, the dependency in
   `pyproject.toml`, and the hashes in `requirements.txt`.
5. Review the diff and run the full test matrix and the offline smoke test.

Never copy a newly downloaded checksum into the manifest just to make
verification pass.
