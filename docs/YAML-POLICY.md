# YAML anchors and aliases

Anchors and aliases reuse YAML values. Analysis treats their resolved content in
the same way as equivalent inline YAML, including job permissions, secret
references, runner selections, matrices and environment targets.

Before constructing Python objects or evaluating rules, the entire composed
document graph is checked. Shared subtrees are memoized for validation work, but
every reference contributes its full logical cost to the expansion limits:

- At most 500 alias references in source tokens.
- At most 200,000 expanded nodes, including mapping keys and unused fields.
- At most 4 MiB of expanded UTF-8 scalar content, including keys.
- Expanded graph depth at most 50, including alias paths.

Existing source limits (256 KiB/file, 60,000 tokens and lexical depth 50) still
apply. Cycles, undefined/duplicate anchors, unsupported tags, duplicate keys and
YAML merge keys (`<<`) produce an explicit analysis error. No proposed code runs.
These are conservative analysis bounds, not claims about GitHub's validation.

The expression walker retains a defensive visit budget. Whole-document graph
validation also protects matrix inspection, comparisons and other traversals;
an expression-only counter would leave those paths exposed to alias expansion.

An unchanged file is skipped, as before. The scanner is a delta review aid and
does not certify that all pre-existing repository YAML is valid. Invalid changed
input produces error; findings established in other files remain available.

See [alias validation](ALIAS-VALIDATION.md) for reproducible cases and hosted evidence.
