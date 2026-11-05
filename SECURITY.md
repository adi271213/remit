# Security

## Reporting a vulnerability

Report vulnerabilities in this tool privately through
[GitHub security advisories](https://github.com/adi271213/remit/security/advisories/new).
Include the affected version or commit, a minimal reproduction and the impact.
Don't include real credentials or private repository content. Use public issues
for ordinary bugs.

This is a single-maintainer, experimental project with no guaranteed response
time. Fixes go into new releases; older tags are not patched.

## Scope

The tool reports a fixed set of workflow configuration changes. It is not a
complete supply-chain scanner, it can't prove that a PR is safe, and it is not a
merge gate: a PR can modify the workflow that runs it.

When installing:

- pin the Action to a reviewed full commit SHA;
- give the job read-only permissions;
- require review of changes under `.github/` (for example with `CODEOWNERS`),
  since Remit reports but never blocks;
- set `default-permissions` only from the trusted calling workflow.
