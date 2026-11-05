"""Whether a job's if: condition rules out runs caused by pull requests.

GitHub expressions are parsed into a small tree and evaluated with three-valued logic:
anything this module cannot know (functions, other properties) is UNKNOWN, and a
condition only rules a case out when it is definitely false. Unparseable conditions
rule nothing out.
"""
import re

UNKNOWN = object()
# workflow_run.event values whose triggering run can carry pull request content.
PULL_REQUEST_EVENTS = ("pull_request", "pull_request_target", "pull_request_review",
                       "pull_request_review_comment", "issue_comment", "merge_group", "workflow_run")
WORKFLOW_RUN_EVENT = "github.event.workflow_run.event"
TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)|(?P<op>==|!=|<=|>=|&&|\|\||[!<>(),\[\]])"
                   r"|(?P<name>[A-Za-z_][A-Za-z0-9_.*-]*(?:\[[^\]]*\])*[A-Za-z0-9_.*-]*))")
STATUS_FUNCTIONS = {"always", "failure", "cancelled"}


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
        out.append((kind, match.group(kind)))
        position = match.end()
    return out


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i = tokens, 0

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

    def disjunction(self):
        node = self.conjunction()
        while self.peek()[1] == "||":
            self.take()
            node = ("or", node, self.conjunction())
        return node

    def conjunction(self):
        node = self.comparison()
        while self.peek()[1] == "&&":
            self.take()
            node = ("and", node, self.comparison())
        return node

    def comparison(self):
        node = self.unary()
        while self.peek()[1] in ("==", "!=", "<", ">", "<=", ">="):
            operator = self.take()[1]
            node = ("cmp", operator, node, self.unary())
        return node

    def unary(self):
        if self.peek()[1] == "!":
            self.take()
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        kind, value = self.take()
        if value == "(":
            node = self.disjunction()
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
                    args.append(self.disjunction())
                    if self.peek()[1] == ",":
                        self.take(",")
                self.take(")")
                return ("call", value.casefold(), args)
            return ("prop", value.casefold())
        raise _Unsupported


def _truth(value):
    if value is UNKNOWN:
        return UNKNOWN
    return bool(value) if not isinstance(value, float) else value != 0


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
        left, right = _truth(_evaluate(node[1], facts)), _truth(_evaluate(node[2], facts))
        decisive = kind == "or"  # True decides an or; False decides an and.
        if left is decisive or right is decisive:
            return decisive
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        return not decisive
    if kind == "cmp":
        operator, left, right = node[1], _evaluate(node[2], facts), _evaluate(node[3], facts)
        if left is UNKNOWN or right is UNKNOWN or operator not in ("==", "!="):
            return UNKNOWN
        if isinstance(left, str) and isinstance(right, str):
            equal = left.casefold() == right.casefold()
        else:
            equal = left == right
        return equal if operator == "==" else not equal
    return UNKNOWN


def _parse(condition):
    if isinstance(condition, bool):
        return ("lit", condition)
    if not isinstance(condition, str) or not condition.strip():
        return None
    try:
        return _Parser(_tokens(condition)).parse()
    except (_Unsupported, RecursionError):
        return None


def _calls(node):
    if not isinstance(node, tuple):
        return set()
    found = {node[1]} if node[0] == "call" else set()
    for part in node[1:]:
        if isinstance(part, tuple):
            found |= _calls(part)
        elif isinstance(part, list):
            for item in part:
                found |= _calls(item)
    return found


def excludes_pull_request_runs(condition) -> bool:
    """True when, for a workflow_run trigger, the condition is false whenever the triggering run
    came from a pull request event."""
    tree = _parse(condition)
    if tree is None:
        return False
    return all(_truth(_evaluate(tree, {WORKFLOW_RUN_EVENT: event, "github.event_name": "workflow_run"})) is False
               for event in PULL_REQUEST_EVENTS)


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
