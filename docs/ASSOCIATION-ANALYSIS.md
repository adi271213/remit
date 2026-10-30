# Runner/environment associations

Version 0.0.3 closes a gap in v0.0.2: independent sets can stay the
same while a matrix changes which runner selects each environment.

```text
base: ubuntu-latest -> production; self-hosted -> staging
head: ubuntu-latest -> staging;    self-hosted -> production
```

Both revisions select the same runners and environments. The head introduces a
new configured pairing between `self-hosted` and `production`. WF008 suggests
review of that pairing. It does not establish that the runner exists, that any
secret is available, or that the change is an exploitable privilege escalation.

## Reproduce locally

From a local installation of version 0.0.3 or later:

```sh
workflow-privilege-check scan --dirs examples/association-base examples/association-head --format markdown
workflow-privilege-check scan --dirs examples/association-base examples/association-head --format json
```

The expected result is `analysis: complete`, `review: suggested`, with one WF008
finding for job `deploy`. Its before/after values retain the resolved pairs.
The fixture files are synthetic input data; the scanner does not execute them.
Earlier v0.0.2 installations do not contain WF008.

## Bounded comparison

Runner labels, runner groups and environment names are resolved together from
each supported static matrix row. No cross product is reconstructed from their
independent unions. The same include/exclude expansion and 256-row limit apply
as in the existing context rules. Label and environment case, label order,
duplicate pairs, row order and unrelated matrix fields do not add pairings.

WF008 covers newly introduced pairs when the individual runner targets and
environment-name sets stay unchanged. Removing pairs alone does not produce
WF008. Changes already reported by WF005 or WF007 retain those findings instead
of receiving a second association warning. Ordinary recognized hosted runner
version updates stay under the existing runner policy.

Changed associations involving an unresolved selector remain incomplete when
their relationship cannot be established. They do not receive invented pairs.
Identical unresolved selectors and matrices can still compare symbolically
under the existing disclosed fixed-context assumption.
Equivalent label/name case, runner string/list/mapping forms and whitespace in
direct matrix references do not create association uncertainty. Matrix variable
names resolve case-insensitively; conflicting duplicate names are incomplete.
Distinct matrix field bindings remain distinct, so rebinding rows is still
compared.

## Assessment boundary

This compares configured selections within one matched job ID. It does not
trace secret delivery, step conditions, trigger reachability, runner inventory,
effective environment policies, dependencies between jobs or reusable-workflow
bodies. Token permissions and literal secret references remain separate per-job
comparisons. This is not a general capability graph or an authorization decision.

The regressions include include-only matrices, include overrides, exclude edits,
label/group conjunctions, equal-set swaps, additions without removals, quiet
normalization edits, unresolved selectors and matrix-size boundaries. An
exhaustive small-relation test enumerates all nonempty subsets of four synthetic
runner/environment pairs and checks comparisons with equal individual sets.
These are correctness tests, not independent security labels or production
precision/recall measurements.
