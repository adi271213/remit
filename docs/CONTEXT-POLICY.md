# Runner and environment context policy

WF005, WF007 and WF008 identify review-sensitive configured contexts, not verified
privilege escalation. They do not query GitHub runner inventory, environment
secrets, deployment approvals, branch rules or effective access.

## WF005 — runner selection

A new or changed selection merits review when it contains the explicit
`self-hosted` label, an unfamiliar/custom label, a group, or an unresolved
expression. Unknown labels/groups are not called self-hosted: GitHub also uses
larger runners and self-hosted runners can omit the default label. The convention
list in `src/privilege_check/contexts.py` keeps ordinary standard hosted version
updates quiet; it is not an inventory or guarantee of runner ownership.
The convention list is checked against GitHub's
[standard runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and retains historical labels for comparisons with older workflows.

Labels are normalized case-insensitively, duplicate labels are removed, and
label order / string versus equivalent mapping forms do not create findings.
Moving from a known custom/self-hosted selection to only recognized hosted
labels is not a WF005 finding. Existing selections do not create new findings.

## WF007 — environment selection

Additions, removals and changes to selected environment names merit review.
String and mapping `name` forms normalize; names are case insensitive. URL-only
edits do not create findings. A new environment can make scoped secrets/variables
available after protection rules pass, while also adding approval constraints.
Removing it can drop those constraints and scoped access. Neither direction is
universally more privileged. Existing secret text can remain unchanged while the
selected environment changes; WF007 is independent of WF004.

Environment URL/deployment metadata, remote policy changes and actual availability
remain outside the comparison. No secret values are retrieved.

## WF008 — runner/environment associations (0.0.3)

When individual runner targets and environment-name sets stay unchanged, a new
pairing between them merits review. The comparison retains the labels, group
and environment from each resolved matrix row. Before/after `pairs` provide
configured evidence; they do not prove secret delivery or runtime authority.
Removing pairs alone does not introduce an association finding. Changes already
reported by WF005 or WF007 are not duplicated. See the
[reproducible example and boundaries](ASSOCIATION-ANALYSIS.md).

## Expressions and matrices

Direct `${{ matrix.field }}` string selections resolve against literal matrices
of at most 256 combinations. Exclusions apply before includes; includes augment
compatible original combinations or append a combination. Other expressions,
non-string selection results, empty selections and oversized/dynamic matrices
cannot be fully resolved.
Since 0.0.3, the resolver follows GitHub's case-insensitive matrix variable names.
Ambiguous duplicate names that differ only by case remain incomplete.
Since 0.0.4, direct field names also accept hyphens, for example
`${{ matrix.runner-name }}`, as allowed by
[GitHub's expression property syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#available-contexts).

Runner comparisons preserve label/group combinations within each matrix row. An equal combined set of labels does not establish equal runner selections.
When only the combinations change, WF005 includes the individual `targets` in
its before/after values. Row ordering, duplicates and unrelated matrix fields
do not create findings. See the [0.0.1 limitation](KNOWN-LIMITATIONS.md).
WF008 additionally preserves runner/environment pairings within
supported static matrix rows. It does not trace which secrets reach a runner.
Earlier 0.0.2 installations compare the two selections independently.

A changed unresolved selector is incomplete and still reports the known selector
change. If an unchanged selector's matrix changes but targets cannot be resolved,
the result is incomplete without inventing a target-change finding. Identical
unresolved selector/matrix pairs compare symbolically, disclosing an assumption
that external runtime context is fixed. Runtime expression evaluation is never
performed. Unresolved changes remain incomplete.
If individually unchanged target sets cannot establish a changed association
because a selector is unresolved, the association comparison is also incomplete.

References: [runner selection](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
and [environment protection/secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
