# Security reporting and scope

This experimental tool reports supported configuration changes. It is not a
complete supply-chain scanner, a proof of PR safety, or an unbypassable merge gate.

For a vulnerability in this tool, [report it privately on GitHub](https://github.com/adi271213/workflow-privilege-check/security/advisories/new).
Private vulnerability reporting is enabled. Include the affected commit/version,
a minimal reproduction and the observed impact. Do not include real credentials
or private repository content. Public issues are suitable for ordinary bugs and
synthetic reproductions.

Check the [latest release](https://github.com/adi271213/workflow-privilege-check/releases/latest)
and [known release limitations](docs/KNOWN-LIMITATIONS.md) before reporting an
already documented issue. Older tags remain available for reproducibility; their
availability does not imply that fixes will be backported. This experimental
project has no guaranteed response time.

Install the Action from a reviewed full commit SHA, outside the proposed checkout.
Use read-only permissions and keep default-permission assertions under trusted
operator control. The advisory pilot must remain outside required merge checks.
