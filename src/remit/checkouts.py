"""Which actions/checkout steps stopped setting persist-credentials: false.

Each checkout on the head side is first matched to the same step on the base side, and only
then are their settings compared. Counting safe checkouts is not enough: a checkout that
loses the setting and an unrelated safe checkout added elsewhere leave the count unchanged.
"""
from dataclasses import dataclass, field
from difflib import SequenceMatcher

# Above this many step pairs in the changed part of a steps list, steps are not aligned by
# content (the comparison is quadratic); what is left unmatched is reported as ambiguous.
MAX_ALIGNMENT = 250_000


@dataclass(frozen=True)
class Checkout:
    """An actions/checkout step and where it sits. Carried in the codes list."""
    sequence: str            # the steps list it belongs to: file, and job name for a workflow
    index: int               # its position in that list
    place: str               # its repository and path inputs
    step_id: str | None      # its explicit id, if it has one
    persists: bool           # whether the token is kept for later steps
    detail: str              # how it is shown
    file: str
    line: int | None
    steps: tuple = field(default=(), compare=False)  # a signature for every step in the list


def aligned(base: tuple, head: tuple) -> dict[int, int]:
    """head index -> base index for the steps that are in both lists, in the same order."""
    shortest = min(len(base), len(head))
    prefix = 0
    while prefix < shortest and base[prefix] == head[prefix]:
        prefix += 1
    suffix = 0
    while suffix < shortest - prefix and base[-1 - suffix] == head[-1 - suffix]:
        suffix += 1
    pairs = {index: index for index in range(prefix)}
    for offset in range(1, suffix + 1):
        pairs[len(head) - offset] = len(base) - offset
    middle_base, middle_head = base[prefix:len(base) - suffix], head[prefix:len(head) - suffix]
    if middle_base and middle_head and len(middle_base) * len(middle_head) <= MAX_ALIGNMENT:
        matcher = SequenceMatcher(None, middle_base, middle_head, autojunk=False)
        for block in matcher.get_matching_blocks():
            for offset in range(block.size):
                pairs[prefix + block.b + offset] = prefix + block.a + offset
    return pairs


def _unique(checkouts) -> list:
    """One entry per step: an action used twice by a job lists its checkouts twice."""
    return list({(c.sequence, c.index): c for c in checkouts}.values())


def weakened(base, head) -> list[tuple[Checkout, bool]]:
    """Head checkouts that keep the token although the matching base checkout did not.

    Each is (checkout, certain). A step is matched by its explicit id, or else by its position
    among the unchanged steps around it. Added and deleted checkouts are not weakenings.
    certain is False when the steps cannot be told apart: a safe checkout disappeared and an
    unsafe one of the same repository and path appeared without a match between them (a move,
    a rewrite, a changed id), or a safe one was added directly beside the one that changed.
    """
    base, head = _unique(base), _unique(head)
    base_lists = {}
    for checkout in base:
        base_lists.setdefault(checkout.sequence, []).append(checkout)
    head_lists = {}
    for checkout in head:
        head_lists.setdefault(checkout.sequence, []).append(checkout)

    matches, used = {}, set()   # head (sequence, index) -> base checkout; matched base keys
    for sequence, items in head_lists.items():
        candidates = base_lists.get(sequence, [])
        if not candidates:
            continue
        ids = {}
        for checkout in candidates:
            if checkout.step_id:
                ids.setdefault(checkout.step_id, []).append(checkout)
        head_ids = [c.step_id for c in items if c.step_id]
        for checkout in items:  # explicit ids first: they survive reordering
            same = ids.get(checkout.step_id, []) if checkout.step_id else []
            if len(same) == 1 and head_ids.count(checkout.step_id) == 1 and same[0].place == checkout.place:
                matches[(sequence, checkout.index)] = same[0]
                used.add((sequence, same[0].index))
        by_index = {c.index: c for c in candidates}
        pairs = aligned(candidates[0].steps, items[0].steps)
        for checkout in items:
            other = by_index.get(pairs.get(checkout.index))
            if (sequence, checkout.index) in matches or other is None or (sequence, other.index) in used:
                continue
            if other.place == checkout.place:
                matches[(sequence, checkout.index)] = other
                used.add((sequence, other.index))

    by_position = {(checkout.sequence, checkout.index): checkout for checkout in head}

    def beside_a_new_safe_checkout(checkout) -> bool:
        """True when a safe checkout of the same repository and path was added right next to
        this one. Then the text reads the same whether this step lost the setting, or kept
        its place while an unsafe copy was put in front of it."""
        for step in (-1, 1):
            index = checkout.index + step
            while 0 <= index < len(checkout.steps) and checkout.steps[index] == checkout.steps[checkout.index]:
                other = by_position.get((checkout.sequence, index))
                if other is not None and not other.persists and (checkout.sequence, index) not in matches:
                    return True
                index += step
        return False

    found = [(checkout, not beside_a_new_safe_checkout(checkout)) for checkout in head
             if (other := matches.get((checkout.sequence, checkout.index))) is not None
             and not other.persists and checkout.persists]
    # What could not be matched: safe checkouts that are gone, unsafe ones that are new.
    lost = {}
    for checkout in base:
        if (checkout.sequence, checkout.index) not in used and not checkout.persists:
            lost[checkout.place] = lost.get(checkout.place, 0) + 1
    for checkout in sorted(head, key=lambda c: (c.file, c.index)):
        if (checkout.sequence, checkout.index) not in matches and checkout.persists and lost.get(checkout.place):
            lost[checkout.place] -= 1
            found.append((checkout, False))
    return sorted(found, key=lambda item: (item[0].file, item[0].index))
