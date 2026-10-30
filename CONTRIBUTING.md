# Contributing

Workflow Privilege Check reports selected configuration changes between commits.
Keep contributions small enough to review and reproduce. A finding is a prompt
for review, including intentional changes; it is not a vulnerability claim.

## Development

Use Python 3.11 or newer and Git:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python scripts/validate.py
python scripts/offline_smoke.py
```

The validator runs the full synthetic, unit and local Git/Action integration
suite and writes ignored `validation-results.json`. CI repeats it on Python
3.11 through 3.14 and runs the Action in a disconnected Linux network namespace.
To run one test file, use `python -m unittest discover -s tests -p 'test_contexts.py'`.

See the [architecture](docs/ARCHITECTURE.md) for module responsibilities and trust
boundaries. The CLI installation uses PyPI; the Action uses its checked-in,
hash-verified dependency bundle. See [dependency maintenance](vendor/README.md).

## Changing behavior

For a rule or parser change, add a regression that demonstrates the issue and a
nearby case that should stay quiet. Check incomplete/error cases as well as
findings. Known findings must survive uncertainty in unrelated supported fields.
Keep analysis deterministic and local: it must not execute proposed code, fetch
remote dependencies or inspect live repository/cloud policy.

Update the relevant policy and changelog when supported behavior changes. Keep
rule IDs stable. Report `schemaVersion` is independent of package version; review
consumer compatibility before changing the JSON contract. Findings alone must
not silently become merge enforcement.

Changes to the calling workflow need tests of its actual shell steps. Action
controller, installation or dependency changes also need the offline smoke test;
run the hosted contract and a disposable consumer installation when those paths
change. [Validation](VALIDATION.md) distinguishes local checks from hosted tests.

For rule changes, replay the [hash-pinned historical cases](benchmarks/README.md).
Inspect new facts separately from the frozen legacy labels. Do not relabel a case
just to make a test pass, or describe the replay as independently measured accuracy.

## Pull requests and reports

Explain the observed problem, the resulting behavior and the checks you ran.
Include a small public or synthetic example for bugs. Avoid credentials, private
logs and unnecessary repository content. Report vulnerabilities through
[private security reporting](SECURITY.md).

Changes to release tags, version numbers and installation pins belong in a
separately validated release. Existing tags and evidence remain reproducible.

Source distributions include the scripts, test fixtures and bundled dependency
needed to run the same validator after extraction. The installed wheel contains
the CLI package; it does not install the GitHub Action into site-packages.

## Repository rules

`main` requires a pull request, resolved review threads and up-to-date Python
3.11 through 3.14 CI from GitHub Actions. The rules block force pushes and deletion,
with no bypass actors. The required approval count is currently zero because this
repository has one maintainer. Requiring a PR does not claim independent review.

For `v*` tags, creation is limited to the release owner's account. Separate rules
block updates and deletion without a bypass, including for the owner. Repository
administrators can still edit the rules; these settings protect the release
process and are not a guarantee against an administrator changing policy.
See the [active rules](https://github.com/adi271213/workflow-privilege-check/rules).
