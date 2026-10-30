"""Configured runner/environment changes, without inventory or runtime claims."""
import re
from itertools import product
from .expressions import IDENTIFIER

# A deliberately explicit convention list, not discovery of runner ownership.
# Unknown/custom labels and groups merit review instead of being called self-hosted.
HOSTED_LABELS = set("""ubuntu-latest ubuntu-slim ubuntu-22.04 ubuntu-24.04 ubuntu-26.04
ubuntu-22.04-arm ubuntu-24.04-arm ubuntu-26.04-arm windows-latest windows-2022 windows-2025
windows-2025-vs2026 windows-11-arm windows-11-vs2026-arm macos-latest macos-13
macos-14 macos-15 macos-26 xcode-27
macos-15-intel macos-26-intel macos-14-large macos-14-xlarge macos-15-large
macos-15-xlarge macos-26-large macos-26-xlarge""".split())
MATRIX = re.compile(r"\s*\$\{\{\s*(?i:matrix)\.(" + IDENTIFIER + r")\s*\}\}\s*")


def _matrix(job):
    strategy = (job or {}).get("strategy", {})
    return strategy.get("matrix") if isinstance(strategy, dict) else None


def _matrix_rows(matrix):
    """Expand a small literal matrix using GitHub's exclude/include ordering."""
    def fields(mapping):
        folded = {key.casefold(): value for key, value in mapping.items()}
        return folded if len(folded) == len(mapping) else None

    def dynamic(value):
        if isinstance(value, str): return "${{" in value
        if isinstance(value, dict): return any(dynamic(x) for x in value.values())
        if isinstance(value, list): return any(dynamic(x) for x in value)
        return False
    if dynamic(matrix): return None
    axes = fields({k: v for k, v in matrix.items() if k not in ("include", "exclude")})
    include, exclude = matrix.get("include", []), matrix.get("exclude", [])
    if axes is None or any(not isinstance(v, list) or not v for v in axes.values()): return None
    if any(not isinstance(v, list) or len(v) > 256 or any(not isinstance(x, dict) for x in v)
           for v in (include, exclude)): return None
    include, exclude = ([fields(item) for item in items] for items in (include, exclude))
    if any(item is None for item in include + exclude): return None
    size = 1
    for values in axes.values():
        size *= len(values)
        if size > 256: return None
    originals = [dict(zip(axes, values)) for values in product(*axes.values())] if axes else []
    originals = [row for row in originals if not any(all(k in row and row[k] == v for k, v in item.items()) for item in exclude)]
    rows = [row.copy() for row in originals]
    appended = []
    for item in include:
        matched = False
        for original, row in zip(originals, rows):
            if all(k not in original or original[k] == v for k, v in item.items()):
                row.update(item)
                matched = True
        if not matched: appended.append(item.copy())
    return rows + appended if len(rows) + len(appended) <= 256 else None


def _options(value, job):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Runner/environment selectors must be nonempty strings.")
    if "${{" not in value:
        return [value], False
    match = MATRIX.fullmatch(value)
    matrix = _matrix(job)
    if not match or not isinstance(matrix, dict):
        return [], True
    field = match.group(1).casefold()
    rows = _matrix_rows(matrix)
    if not rows or any(field not in row for row in rows):
        return [], True
    values = [row[field] for row in rows]
    if not values or any(not isinstance(x, str) or not x.strip() or "${{" in x for x in values):
        return [], True
    return values, False


def _runner(job):
    if not job or "runs-on" not in job:
        return {"labels": [], "groups": []}, False
    value = job["runs-on"]
    groups = []
    unknown = False
    if isinstance(value, dict):
        if not value or set(value) - {"group", "labels"}:
            raise ValueError("Unsupported runs-on mapping.")
        if "group" in value:
            groups, unknown = _options(value["group"], job)
        value = value.get("labels", [])
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("Unsupported runs-on declaration.")
    if not value and not groups and not unknown:
        raise ValueError("Empty runs-on selection.")
    labels = []
    for label in value:
        options, unresolved = _options(label, job)
        labels.extend(x.casefold() for x in options)
        unknown |= unresolved
    return {"labels": sorted(set(labels)), "groups": sorted(set(groups))}, unknown


def _environment(job):
    if not job or "environment" not in job:
        return {"names": []}, False
    value = job["environment"]
    if isinstance(value, dict):
        if "name" not in value:
            raise ValueError("Environment mapping needs a name.")
        value = value["name"]
    names, unknown = _options(value, job)
    # Environment names are case insensitive. URL-only edits do not change context.
    return {"names": sorted({x.casefold() for x in names})}, unknown


def _runner_targets(job, *, include_environment=False):
    """Keep resolved selectors from each matrix row together, never cross-join unions."""
    if not job or "runs-on" not in job:
        return []
    value = job["runs-on"]
    group = value.get("group") if isinstance(value, dict) else None
    labels = value.get("labels", []) if isinstance(value, dict) else value
    if isinstance(labels, str):
        labels = [labels]
    environment = job.get("environment") if include_environment else None
    if isinstance(environment, dict):
        environment = environment.get("name")
    selectors = labels + ([group] if group is not None else []) + ([environment] if environment is not None else [])
    rows = _matrix_rows(_matrix(job)) if any(MATRIX.fullmatch(x) for x in selectors) else [{}]
    # Called only after the corresponding resolvers established static values.
    if not rows:
        raise ValueError("Runner target combinations cannot be resolved.")

    def selected(text, row):
        match = MATRIX.fullmatch(text)
        return row[match.group(1).casefold()] if match else text

    targets = set()
    for row in rows:
        label_set = tuple(sorted({selected(label, row).casefold() for label in labels}))
        groups = (selected(group, row),) if group is not None else ()
        name = selected(environment, row).casefold() if environment is not None else None
        targets.add((label_set, groups, name))
    return [{"labels": list(labels), "groups": list(groups),
             **({"environment": name} if include_environment else {})}
            for labels, groups, name in sorted(targets)]


def _context_selection(job):
    def selector(value, *, fold=False):
        match = MATRIX.fullmatch(value)
        if match:
            return "matrix", match.group(1).casefold()
        if "${{" in value:
            return "expression", value
        return "literal", value.casefold() if fold else value

    runner = job.get("runs-on")
    group = runner.get("group") if isinstance(runner, dict) else None
    labels = runner.get("labels", []) if isinstance(runner, dict) else runner
    if isinstance(labels, str):
        labels = [labels]
    # Normalize syntax without erasing which matrix field each row selects.
    runner = (tuple(sorted({selector(label, fold=True) for label in labels})),
              selector(group) if group is not None else None)
    environment = job.get("environment")
    if isinstance(environment, dict):
        environment = environment.get("name")
    return runner, selector(environment, fold=True), _matrix(job)


def _compare_associations(before, after, unresolved):
    """Close the equal-marginals gap; individual context changes have their own rules."""
    if not before or not all(field in job for job in (before, after) for field in ("runs-on", "environment")):
        return [], []
    if _context_selection(before) == _context_selection(after):
        return [], []
    if not unresolved["runs-on"] and _runner_targets(before) != _runner_targets(after):
        return [], []
    if any(unresolved.values()):
        return [], [("incomplete", "Changed runner/environment associations cannot be fully resolved; only direct static matrix fields are supported.")]
    old = _runner_targets(before, include_environment=True)
    new = _runner_targets(after, include_environment=True)
    if not any(pair not in old for pair in new):
        return [], []
    return [{"rule": "WF008", "before": {"pairs": old}, "after": {"pairs": new},
             "message": "New runner/environment pairing introduced while individual target sets stay unchanged. Review the paired runner and environment-scoped settings; actual access and protection policies are not verified."}], []


def compare_contexts(before, after):
    findings, diagnostics, assumptions = [], [], []
    unresolved = {}
    for field, rule, resolve in (("runs-on", "WF005", _runner), ("environment", "WF007", _environment)):
        try:
            old, old_unknown = resolve(before)
            new, new_unknown = resolve(after)
        except ValueError as exc:
            diagnostics.append(("error", str(exc)))
            continue
        unresolved[field] = old_unknown or new_unknown
        old_selector, new_selector = (before or {}).get(field), after.get(field)
        if field == "environment":
            if isinstance(old_selector, dict): old_selector = old_selector.get("name")
            if isinstance(new_selector, dict): new_selector = new_selector.get("name")
        if old_unknown or new_unknown:
            if old_selector == new_selector and _matrix(before) == _matrix(after):
                assumptions.append(f"Unchanged unresolved {field} selector/matrix compares symbolically; external runtime context is assumed fixed and is not observed.")
                continue
            diagnostics.append(("incomplete", f"Changed {field} selection cannot be fully resolved; only direct static matrix fields are supported."))
            if old_selector == new_selector:
                # A matrix/context edit does not prove that the unchanged
                # unresolved selector targets a different resource.
                continue
            old = {**old, "unresolved": old_unknown}
            new = {**new, "unresolved": new_unknown}
        elif old == new:
            if field != "runs-on":
                continue
            if old_selector == new_selector and _matrix(before) == _matrix(after):
                continue
            try:
                old_targets, new_targets = _runner_targets(before), _runner_targets(after)
            except ValueError as exc:
                diagnostics.append(("error", str(exc)))
                continue
            if old_targets == new_targets:
                continue
            # Equal unions can hide changed label/group combinations. Include
            # row targets so the finding explains the actual configured change.
            old, new = {**old, "targets": old_targets}, {**new, "targets": new_targets}
        if field == "runs-on":
            if not (old_unknown or new_unknown) and not (new["groups"] or set(new["labels"]) - HOSTED_LABELS):
                continue
            message = "Runner selection changed to a self-hosted, custom/group, or unresolved context. Review infrastructure access; ownership and execution are not verified."
        else:
            message = "Environment selection changed. Review scoped configuration and approval requirements; secret availability and protection policies are not verified."
        findings.append({"rule": rule, "before": old, "after": new, "message": message})
    if not findings and not diagnostics:
        try:
            changes, issues = _compare_associations(before, after, unresolved)
            findings.extend(changes)
            diagnostics.extend(issues)
        except ValueError as exc:
            diagnostics.append(("error", str(exc)))
    return findings, diagnostics, assumptions
