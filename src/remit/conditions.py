"""Whether a job's if: condition rules out runs caused by pull requests.

GitHub expressions are parsed into a small tree and evaluated with three-valued logic:
anything this module cannot know (functions, other properties) is UNKNOWN, and a
condition only rules a case out when it is definitely false. Unparseable conditions
rule nothing out.
"""
import re

UNKNOWN = object()
# A value that cannot be known but whose truthiness can, as when one side of && is unknown
# and the other is false. Such values are never compared.
FALSY_UNKNOWN = object()
TRUTHY_UNKNOWN = object()
_UNKNOWNS = (UNKNOWN, FALSY_UNKNOWN, TRUTHY_UNKNOWN)
# workflow_run.event values whose triggering run can carry pull request content.
PULL_REQUEST_EVENTS = ("pull_request", "pull_request_target", "pull_request_review",
                       "pull_request_review_comment", "issue_comment", "merge_group", "workflow_run")
WORKFLOW_RUN_EVENT = "github.event.workflow_run.event"
TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)|(?P<op>==|!=|<=|>=|&&|\|\||[!<>(),\[\]])"
                   r"|(?P<name>[A-Za-z_][A-Za-z0-9_.*-]*(?:\[[^\]]*\])*[A-Za-z0-9_.*-]*))")
STATUS_FUNCTIONS = {"always", "failure", "cancelled"}
# Budgets. A condition beyond them is not evaluated and rules nothing out. Chains of ||, && and
# comparisons are held as flat lists and folded in a loop, so their length costs no stack;
# only parentheses, ! and function arguments nest.
MAX_TOKENS = 20_000
MAX_NESTING = 50


class _Unsupported(Exception):
    pass


def _tokens(text):
    position, out = 0, []
    text = text.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    while position < len(text.rstrip()):
        match = TOKEN.match(text, position)
        if not match or match.end() == position:
            raise _Unsupported
        kind = match.lastgroup
        if len(out) >= MAX_TOKENS:
            raise _Unsupported
        out.append((kind, match.group(kind)))
        position = match.end()
    return out


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i, self.nesting = tokens, 0, 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self, value=None):
        token = self.peek()
        if token[0] is None or (value is not None and token[1] != value):
            raise _Unsupported
        self.i += 1
        return token

    def parse(self):
        tree = self.disjunction()
        if self.i != len(self.tokens):
            raise _Unsupported
        return tree

    def nested(self, parse):
        """parse() one level deeper, within the nesting budget."""
        self.nesting += 1
        if self.nesting > MAX_NESTING:
            raise _Unsupported
        node = parse()
        self.nesting -= 1
        return node

    def disjunction(self):
        operands = [self.conjunction()]
        while self.peek()[1] == "||":
            self.take()
            operands.append(self.conjunction())
        return operands[0] if len(operands) == 1 else ("or", operands)

    def conjunction(self):
        operands = [self.comparison()]
        while self.peek()[1] == "&&":
            self.take()
            operands.append(self.comparison())
        return operands[0] if len(operands) == 1 else ("and", operands)

    def comparison(self):
        first, rest = self.unary(), []
        while self.peek()[1] in ("==", "!=", "<", ">", "<=", ">="):
            operator = self.take()[1]
            rest.append((operator, self.unary()))
        return ("cmp", first, rest) if rest else first

    def unary(self):
        negations = 0
        while self.peek()[1] == "!":
            self.take()
            negations += 1
        node = self.primary()
        # !!x is x's truth value, !x its opposite: more than two say nothing new.
        for _ in range(2 - negations % 2 if negations > 1 else negations):
            node = ("not", node)
        return node

    def primary(self):
        kind, value = self.take()
        if value == "(":
            node = self.nested(self.disjunction)
            self.take(")")
            return node
        if kind == "str":
            return ("lit", value[1:-1].replace("''", "'"))
        if kind == "num":
            return ("lit", float(value))
        if kind == "name":
            if value in ("true", "false"):
                return ("lit", value == "true")
            if value == "null":
                return ("lit", None)
            if self.peek()[1] == "(":
                self.take("(")
                args = []
                while self.peek()[1] != ")":
                    args.append(self.nested(self.disjunction))
                    if self.peek()[1] == ",":
                        self.take(",")
                self.take(")")
                return ("call", value.casefold(), args)
            return ("prop", value.casefold())
        raise _Unsupported


def _truth(value):
    if value is UNKNOWN:
        return UNKNOWN
    if value is FALSY_UNKNOWN:
        return False
    if value is TRUTHY_UNKNOWN:
        return True
    return bool(value) if not isinstance(value, float) else value != 0


def _kind(value):
    """The GitHub type of a value: null, boolean, number or string (bool is not a number)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string" if isinstance(value, str) else "other"


def _evaluate(node, facts):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "prop":
        return facts.get(node[1], UNKNOWN)
    if kind == "call":
        return UNKNOWN
    if kind == "not":
        value = _truth(_evaluate(node[1], facts))
        return UNKNOWN if value is UNKNOWN else not value
    if kind in ("and", "or"):
        # Like GitHub, && and || return one of their operands, not a boolean:
        # a || b is a if a is truthy, else b; a && b is a if a is falsy, else b.
        decisive = kind == "or"  # a truthy left decides an or; a falsy left decides an and.
        result = _evaluate(node[1][0], facts)
        for operand in node[1][1:]:
            truth = _truth(result)
            if truth is decisive:
                break  # the rest is never evaluated, and cannot change the result
            right = _evaluate(operand, facts)
            if truth is not UNKNOWN:
                result = right
            elif _truth(right) is decisive:
                # The left side is unknown: the result is the left value or the right one.
                result = TRUTHY_UNKNOWN if decisive else FALSY_UNKNOWN
            else:
                result = UNKNOWN
        return result
    if kind == "cmp":
        left = _evaluate(node[1], facts)
        for operator, operand in node[2]:  # a == b == c is (a == b) == c
            left = _compare(operator, left, _evaluate(operand, facts))
        return left
    return UNKNOWN


def _compare(operator, left, right):
    if left in _UNKNOWNS or right in _UNKNOWNS or operator not in ("==", "!="):
        return UNKNOWN
    if _kind(left) != _kind(right):
        # GitHub converts mismatched operands to numbers ('1' == 1, null == '' and
        # '0x1' == 1 are all true). Rather than reproduce those rules, a comparison
        # across types is unknown, so it can never rule a run out.
        return UNKNOWN
    if isinstance(left, str):
        equal = left.casefold() == right.casefold()
    else:
        equal = left == right
    return equal if operator == "==" else not equal


def _parse(condition):
    if isinstance(condition, bool):
        return ("lit", condition)
    if not isinstance(condition, str) or not condition.strip():
        return None
    try:
        return _Parser(_tokens(condition)).parse()
    except (_Unsupported, RecursionError):
        return None


def _calls(node) -> set:
    """The names of the functions called anywhere in a parsed condition."""
    found, pending = set(), [node]
    while pending:
        current = pending.pop()
        if isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, tuple):
            if current and current[0] == "call":
                found.add(current[1])
            pending.extend(part for part in current[1:] if isinstance(part, (tuple, list)))
    return found


def excludes_pull_request_runs(condition) -> bool:
    """True when, for a workflow_run trigger, the condition is false whenever the triggering run
    came from a pull request event."""
    tree = _parse(condition)
    if tree is None:
        return False
    try:
        return all(_truth(_evaluate(tree, {WORKFLOW_RUN_EVENT: event, "github.event_name": "workflow_run"})) is False
                   for event in PULL_REQUEST_EVENTS)
    except RecursionError:  # not expected within the budgets; never a reason to hide a finding
        return False


def workflow_run_excludes_pull_requests(document: dict, name: str) -> bool:
    """True when job name, or a job it needs, only runs for workflow_run runs not caused by pull requests."""
    jobs = document.get("jobs") if isinstance(document.get("jobs"), dict) else {}
    seen, pending = set(), [name]
    while pending:
        current = pending.pop()
        job = jobs.get(current)
        if current in seen or not isinstance(job, dict):
            continue
        seen.add(current)
        if excludes_pull_request_runs(job.get("if")):
            return True
        # A job that needs another runs only after it succeeds, unless its own
        # condition overrides that with a status function.
        tree = _parse(job.get("if"))
        if tree is not None and _calls(tree) & STATUS_FUNCTIONS:
            continue
        if tree is None and isinstance(job.get("if"), str) and job["if"].strip():
            continue
        needs = job.get("needs")
        pending.extend([needs] if isinstance(needs, str) else [n for n in needs if isinstance(n, str)]
                       if isinstance(needs, list) else [])
    return False
