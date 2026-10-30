# Validation and limits

Three different checks answer different questions:

1. `python scripts/validate.py` runs synthetic acceptance, parser, source-reader,
   rule, CLI and Action-controller tests. It writes ignored
   `validation-results.json` with runtime versions and source hashes. It performs
   no hosted Action run or public-PR benchmark.
2. CI runs that suite on Python 3.11–3.14, plus
   `python scripts/offline_smoke.py --network-namespace`. The latter runs the
   actual controller as an unprivileged process in a disconnected Linux network
   namespace, in both modes, against local Git fixtures. It validates outputs and
   token/runner/environment findings, the association finding and
   unresolved-association outcomes without pip or external site packages in
   the controller. `python scripts/offline_smoke.py` provides a local smoke test
   without the Linux-only isolation assertion.
   The current smoke test has six cases in two modes: 12 isolated outcomes per
   Python version. These counts are separate from the hosted contract.
3. [The 74-PR replay](benchmarks/README.md) verifies frozen public workflow hashes
   and exact legacy configured facts. It is selected, correlated and self-labeled,
   and not a production accuracy measurement. New context findings are separate.

A hosted consumer test additionally exercises the public pinned composite Action,
trusted-base checkout, exact head fetch and result interpretation. The published
0.0.4 setup is selected only after candidate consumer tests, both mode contracts
and CI pass. Current run links are retained in [release verification notes](docs/RELEASE-0.0.4.md).
[Historical post-release fork checks](docs/FORK-VALIDATION.md) separately cover
the 0.0.2 runtime in advisory mode, from a different account and fork.
Earlier fork runs remain historical evidence for earlier revisions. No human
security audit or maintainer usefulness result is claimed.

The manual hosted contract builds local Git inputs from `tests/hosted_cases.json`
using `scripts/hosted_fixture.py`; it does not require a disposable repository.
Its 16 cases run in both modes (32 jobs). `tests/test_hosted_fixtures.py` also runs
those Git fixtures through the actual controller locally. These synthetic cases
are correctness regressions, not independent security labels.

Known limitations include YAML merge keys and over-budget/recursive aliases, edited-rename
noise, no execution analysis, no cloud authorization or remote environment-policy
inspection, and bounded expression/matrix support. See the policies linked from
README. An incomplete/error outcome is not a clean analysis even when advisory
execution succeeds. Findings alone do not block merges.

The pre-release bounded-alias update has separate [validation evidence](docs/ALIAS-VALIDATION.md).
