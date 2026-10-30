# Fresh fork installation verification

Verified on 2026-10-28 after publication of 0.0.2. This is hosted integration
verification with synthetic inputs, not an independent security audit or a
maintainer usefulness result.

## Setup and boundary

The PR was authored by `Adij2704` in its fork of the disposable consumer,
`adi271213/workflow-privilege-check-pilot-20261024`. It targeted base
`1973ec266e57db9e45eadace98c33c896d51589d` and used the current public template
from source main `5db2ef70b21458f2d8256e6d4b014a9d11e80297`.

The Action remained pinned to the 0.0.2 runtime:
`edd446b3273f53c5b3fa7cda9d45bc62cfbc8d9f`.
The calling workflow was identical in every revision, with SHA-256
`a061dda94698df3619020099ebd17e2aa5689003136f3c5d0ba02a8e59db21bd`.

All runs used `pull_request`, trusted-base checkout and exact head fetching.
GitHub required approval before each revision ran. The upstream owner inspected
and approved the pinned workflow; logs retain `Adij2704` as the original actor
and the owner as the triggering actor after approval. The approval policy was
left at `first_time_contributors`. No collaborator access was added.

Each scanner job had read-only Contents/Metadata token permissions. Proposed
workflow bodies were read as data. The fixture workflows were never dispatched
or merged. Literal secret names were synthetic; no secret values were supplied.

## Observed outcomes

Every listed advisory scanner job succeeded. Incomplete/error analysis retained
exit code 2 and an explicit warning; it was not converted into a clean result.

| Case | Analysis | Review | Findings | Analysis exit | Run |
|---|---|---|---|---|---|
| neutral | complete | none | 0 | 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40769286169) |
| grants | complete | suggested | 5 | 0 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40769544161) |
| incomplete-unknown | incomplete | unknown | 0 | 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40769652397) |
| error-unknown | error | unknown | 0 | 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40769778990) |
| error-known | error | suggested | 1 | 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40769840534) |
| incomplete-known | incomplete | suggested | 1 | 2 | [run](https://github.com/adi271213/workflow-privilege-check-pilot-20261024/actions/runs/40769952512) |

The grant case reported two WF001 increases (`contents: write`, `id-token: write`),
one WF004 literal secret reference, one WF005 custom/self-hosted runner selection
and one WF007 environment target. These are configured requests/context changes;
effective access in a fork was not asserted.

Unknown inherited defaults produced incomplete analysis. A recursive YAML alias
produced an error. A separate file adding `contents: read` retained its WF001
finding alongside either condition. Logs verified exact base/head identities,
the downloaded Action SHA, report/summary availability and output consistency.

The disposable PR was closed and archived after verification, and the temporary
fork branch was removed. A local Git bundle preserves the synthetic revisions.
GitHub's own validation can separately reject the recursive-alias fixture; these
runs specifically verify that the pinned scanner handles it as data.

## Limits

These fresh fork checks cover the public advisory template only. The earlier
hosted contract covers both modes, but is not a fresh fork test of
`require-complete`. Private authentication, every GitHub approval policy,
self-hosted installation and malicious edits to the calling workflow are outside
this test. Pinning the scanner does not make an editable caller unbypassable.
No new release or tag movement was needed for these checks.
