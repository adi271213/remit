## Review suggested

Base: `directory:sha256:0f74f59804637bf5b8e855153fe7e0b703189d1d7a1699c0b1be09596f22c93f`
Head: `directory:sha256:c6f3b69a45ca538e6bd23a33274aafa8d39d1848c251e566c6ac49cf50a36386`

### .github/workflows/release.yml

Workflow-level change

| Rule | Before | After | Change |
|---|---|---|---|
| WF003 | Not recorded | pull&#95;request&#95;target | Review-sensitive trigger pull&#95;request&#95;target introduced. Review who can invoke it and token/secret access. |

Review:

- WF003: Check who can cause the new event and which revision supplies the executed code. Review token and secret access.

### .github/workflows/release.yml

Job: publish

| Rule | Before | After | Change |
|---|---|---|---|
| WF001 | id-token: none | id-token: write | Job publish is newly configured to request an OIDC identity token. Runtime access is not verified. |
| WF001 | packages: none | packages: write | Job publish is newly configured to use packages: write. Runtime access is not verified. |
| WF004 | Not recorded | PUBLISH&#95;TOKEN | Job publish adds a reference or forwarding path to PUBLISH&#95;TOKEN. Availability and actual access are not verified. |

Review:

- WF001: Confirm that this job needs the new token scopes. Check which events can run it and who controls the code it executes.
- WF004: Confirm why the new secret reference or forwarding path is needed. Review its consumer and the applicable secret scope.

Not recorded means this finding has no value recorded for that side; it does not establish whether a runtime resource exists.


Scope: configured capability changes only. This report does not establish PR safety.
