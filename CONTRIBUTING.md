# Contributing

## Development

Python 3.11+ and Git are required.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python scripts/validate.py
python scripts/offline_smoke.py
pip install ruff==0.16.9 && ruff check
```

To run one test file: `python -m unittest discover -s tests -p 'test_contexts.py'`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the code is organised.

## Tests

| Command | What it covers |
|---|---|
| `python scripts/validate.py` | The full unit and integration suite: rules, parser limits, source readers, CLI, the Action controller, and the template's fetch step against local Git repositories. Writes `validation-results.json` (git-ignored) with versions and source hashes. |
| `python scripts/offline_smoke.py` | Runs the real Action controller against local Git fixtures in both modes. In CI, `--network-namespace` runs it with networking disabled. |
| `scripts/replay_benchmark.py` | Replays [74 historical public PRs](benchmarks/README.md) and checks the expected WF001/WF003/WF004 findings. |
| *Action outcome contract* workflow | Manually dispatched. Runs the published, pinned Action against the fixtures in `tests/hosted_cases.json` in both modes. |

CI runs `ruff check`, plus `validate.py` and the network-isolated smoke test on
Python 3.11–3.14. The repository also runs its own Action on every PR
([`privilege-review.yml`](.github/workflows/privilege-review.yml)), loaded from
the PR's base commit.

## Changing behaviour

- Add a regression test that fails without the change, plus a nearby case that
  should stay quiet. Cover `incomplete`/`error` outcomes too.
- Findings already established must survive uncertainty elsewhere in the file.
- Analysis must stay local: no executing workflow content, no network access, no
  querying live repository settings.
- Keep rule IDs stable. Bump `schemaVersion` only for incompatible changes to the
  JSON report.
- Update [docs/RULES.md](docs/RULES.md) and the `Unreleased` section of the
  [changelog](CHANGELOG.md).
- If report output changes, regenerate `examples/sample-report.md` and
  `examples/sample-report.json` (a test checks them).
- For rule changes, run the replay and look at any new findings. Don't change an
  expected result just to make the replay pass.
- Changes to the Action controller, template or bundled dependency need the
  offline smoke test, and the hosted contract before release.

## Releases

1. Update the version in `pyproject.toml` and `src/privilege_check/__init__.py`,
   and move `Unreleased` entries in the changelog under the new version.
2. Run CI, the offline smoke test, the replay and the hosted contract on the
   release candidate.
3. Tag the release commit and publish a GitHub release. Put links to the CI and
   contract runs in the release notes. Publishing the release runs
   [`publish.yml`](.github/workflows/publish.yml), which checks that the tag
   matches the package version, builds with hash-pinned tools, tests the wheel
   and uploads to PyPI through trusted publishing.
4. Update the pinned SHA in `README.md`, `examples/github-action-template.yml`
   and the contract workflow.

PyPI trusted publishing needs a one-time setup on pypi.org: add a pending
publisher for project `workflow-privilege-check`, owner `adi271213`, repository
`workflow-privilege-check`, workflow `publish.yml`, environment `pypi`.

Tags are never moved or deleted after publication.

## Pull requests

Describe the problem, the new behaviour and the checks you ran. Include a small
public or synthetic example for bugs. Don't include credentials or private logs.
Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

`main` is protected: changes go through a pull request with passing CI on all
four Python versions.
