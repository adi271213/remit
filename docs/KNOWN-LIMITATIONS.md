# Known release limitations

## Expression identifiers in 0.0.3 and earlier (fixed in 0.0.4)

The secret-reference lexer split hyphenated property names. For example,
`${{ inputs.use-secrets }}` was mistaken for a whole-secret reference. When
present in the base, that false baseline could suppress a new literal reference
such as `${{ secrets.DEPLOY_KEY }}` and return `complete / none`. Adding only the
input reference could also produce a false WF004 finding.

Version 0.0.4 keeps full identifiers intact and adds regressions for false
references, missed literal additions, quoted text and dynamic selectors.
It also resolves direct hyphenated matrix fields; older versions report those
changed matrices as incomplete rather than detecting their static associations.
Existing release tags stay unchanged. Upgrade the evaluated installation pin;
a successful report from an older version does not rule out this limitation.

## Runner matrix combinations in 0.0.1 (fixed in 0.0.2)

WF005 in 0.0.1 compares the combined labels and groups across matrix rows. It can
miss a change that rearranges combinations while keeping those combined values
the same. For example, changing these pairs:

```text
base: (prod, x64), (test, arm64)
head: (prod, arm64), (test, x64)
```

changes the runner selection when `runs-on` uses both `${{ matrix.pool }}` and
`${{ matrix.arch }}`. Version 0.0.1 can report `complete / none` for this change.
The same problem affects combinations of a runner group and label. Review these
changes manually when using the 0.0.1 tag or its published full-SHA installation.

Version 0.0.2 preserves each row's label/group combination and
includes the changed targets in WF005 findings. It does not query runner
inventory or prove that a newly selected runner exists or has more authority.
The published 0.0.1 tag remains unchanged.

## Runner/environment associations in 0.0.2 (fixed in 0.0.3)

The published 0.0.2 version compares runner and environment selections
independently. It can miss swapping `production` and `staging` between
`ubuntu-latest` and `self-hosted` when both individual sets remain unchanged.

Version 0.0.3 adds WF008, which compares resolved runner/environment pairs within supported
static matrix rows. See the [reproduction and boundaries](ASSOCIATION-ANALYSIS.md).
It does not trace secret delivery, inspect remote environment policy or establish
actual runtime access. Earlier release tags remain unchanged.

For the broader supported scope, see [README](../README.md#coverage),
[runner/environment policy](CONTEXT-POLICY.md) and [YAML policy](YAML-POLICY.md).
