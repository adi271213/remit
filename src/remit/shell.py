"""A one-pass reading of a shell line, enough to find the name given to a new Git branch.

This is not a shell parser. It splits a line into simple commands and words, keeps track of
quotes and of command substitutions ($(...) and `...`), and never looks at a character more
than once per nesting level, so its cost grows linearly with the line.
"""
import re

# Characters that can end a word or open a quote, an expression or a substitution.
_SPECIAL = re.compile(r"""[\s;&|()'"`\\$]""")
# Inside single quotes only the closing quote matters, and a ${{ }} expression, which GitHub
# replaces before the shell runs and which may contain quotes of its own.
_IN_SINGLE_QUOTES = re.compile(r"'|\$\{\{")
# Options are read strictly: a branch name is only recognised when every option before it is
# listed here, so its meaning is known. An option that might take the next word as its value
# (so that "-b" would be that value, not a flag) ends the search, and nothing is removed.
# git options before the subcommand: those that take a separate argument, and those that take none.
_GIT_OPTIONS_WITH_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"})
_GIT_FLAGS = frozenset({"--no-pager", "-P", "--paginate", "-p", "--no-replace-objects", "--bare",
                        "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs",
                        "--no-optional-locks", "--no-lazy-fetch", "--no-advice"})
# git checkout / git switch options that take no value.
_FLAGS = frozenset({"-q", "--quiet", "-f", "--force", "-t", "--track", "--no-track", "-l", "-m", "--merge",
                    "-d", "--detach", "--guess", "--no-guess", "--progress", "--no-progress",
                    "--discard-changes", "--ignore-other-worktrees", "--recurse-submodules",
                    "--no-recurse-submodules", "--overwrite-ignore", "--no-overwrite-ignore"})
# Options whose value, the next word, is the name of a branch to create.
_NEW_BRANCH_FLAGS = frozenset({"-b", "-B", "-c", "-C", "--orphan", "--create", "--force-create"})
_NEW_BRANCH_PREFIXES = ("--orphan=", "--create=", "--force-create=")
# Clustered short options: value-less letters, then the one that takes the name, as in -qb NAME.
# -bc is not one: it is -b with the name "c".
_NEW_BRANCH_CLUSTER = re.compile(r"-[qftlmd]+[bBcC]")
# A { that does not start ${...}: the shell may expand {a,b} into several words.
_BRACE = re.compile(r"(?<!\$)\{")
MAX_SUBSTITUTION_DEPTH = 8


def commands(text: str) -> list[list[tuple[int, int, list[tuple[int, int]]]]]:
    """The simple commands in text, each a list of words (start, end, substitutions).

    substitutions are the (start, end) spans of the outermost command substitution bodies
    inside the word. An unterminated quote or substitution runs to the end of the text.
    """
    found, words = [], []
    stack = []          # open constructs: '"', '`', or '(' for $( and parentheses inside one
    word_start = None
    substitutions = []
    open_at = depth_at_open = None  # the outermost substitution being read, and the stack depth outside it
    position, length = 0, len(text)

    def end_word(at):
        nonlocal word_start, substitutions
        if word_start is not None:
            words.append((word_start, at, substitutions))
            word_start, substitutions = None, []

    def end_command(at):
        nonlocal words
        end_word(at)
        if words:
            found.append(words)
            words = []

    def close_substitution(at):
        nonlocal open_at, depth_at_open
        if open_at is not None and len(stack) == depth_at_open:
            substitutions.append((open_at, at))
            open_at = depth_at_open = None

    while position < length:
        match = _SPECIAL.search(text, position)
        if match is None:
            if word_start is None:
                word_start = position
            break
        at, char = match.start(), match.group()
        if at > position and word_start is None:
            word_start = position
        top = stack[-1] if stack else None
        position = at + 1
        if char == "\\":
            word_start = at if word_start is None else word_start
            position = at + 2
        elif char == "$" and text.startswith("{{", at + 1):
            word_start = at if word_start is None else word_start
            end = text.find("}}", at + 3)
            position = end + 2 if end >= 0 else length
        elif char == "$" and text.startswith("(", at + 1):
            word_start = at if word_start is None else word_start
            if open_at is None:
                open_at, depth_at_open = at + 2, len(stack)
            stack.append("(")
            position = at + 2
        elif char == "'" and top != '"':
            word_start = at if word_start is None else word_start
            position = length
            while (inner := _IN_SINGLE_QUOTES.search(text, at + 1)) is not None:
                if inner.group() == "'":
                    position = inner.end()
                    break
                end = text.find("}}", inner.end())
                if end < 0:
                    break
                at = end + 1
        elif char == '"':
            word_start = at if word_start is None else word_start
            if top == '"':
                stack.pop()
            else:
                stack.append('"')
        elif char == "`":
            word_start = at if word_start is None else word_start
            if top == "`":
                stack.pop()
                close_substitution(at)
            else:
                if open_at is None:
                    open_at, depth_at_open = at + 1, len(stack)
                stack.append("`")
        elif char == "(" and top in ("(", "`"):
            stack.append("(")
        elif char == ")" and top == "(":
            stack.pop()
            close_substitution(at)
        elif stack:
            word_start = at if word_start is None else word_start  # inside quotes or a substitution
        elif char.isspace():
            if char == "\n":
                end_command(at)
            else:
                end_word(at)
        elif char in ";&|()":
            end_command(at)
        else:
            word_start = at if word_start is None else word_start  # a lone $ or quote character
    if open_at is not None:
        substitutions.append((open_at, length))
    end_command(length)
    return found


def _one_word(word: str) -> bool:
    """False when the shell may turn the word into several: brace expansion such as {a,$REF}."""
    parts, position = [], 0
    while (start := word.find("${{", position)) >= 0:  # ${{ }} expressions are not shell braces
        parts.append(word[position:start])
        end = word.find("}}", start + 3)
        position = end + 2 if end >= 0 else len(word)
    parts.append(word[position:])
    return _BRACE.search("".join(parts)) is None


def new_branch_names(text: str) -> list[tuple[int, int, list[tuple[int, int]]]]:
    """Spans of the names given to branches that git checkout / git switch create in text."""
    names = []
    for words in commands(text):
        # 0: before git; 1: after git; 2: after checkout/switch; 3: the next word is a branch
        # name; 4: nothing more to find in this command; 5: skip a git option's value.
        state = 0
        for start, end, substitutions in words:
            word = text[start:end]
            if state == 0:
                state = 1 if word == "git" else 0
            elif state == 1:
                if word in ("checkout", "switch"):
                    state = 2
                elif word in _GIT_OPTIONS_WITH_VALUE:
                    state = 5
                elif word not in _GIT_FLAGS and not (word.startswith("--") and "=" in word):
                    state = 4  # another subcommand, or an option this reader does not know
            elif state == 5:
                state = 1
            elif state == 2:
                if word in _NEW_BRANCH_FLAGS or _NEW_BRANCH_CLUSTER.fullmatch(word):
                    state = 3
                elif word.startswith(_NEW_BRANCH_PREFIXES):
                    name_start = start + word.index("=") + 1
                    if _one_word(text[name_start:end]):
                        names.append((name_start, end, [span for span in substitutions if span[0] >= name_start]))
                    else:
                        state = 4
                elif word.startswith("-") and word not in _FLAGS and not (word.startswith("--") and "=" in word):
                    state = 4  # "--" or an option that may take the next word as its value
            elif state == 3:
                if _one_word(word):
                    names.append((start, end, substitutions))
                    state = 2
                else:
                    state = 4
    return names


def without_new_branch_names(text: str, _depth: int = 0) -> str:
    """text with the names of branches created by git checkout -b / git switch -c removed.

    The name only labels the new branch; the code checked out comes from the start point after
    it, or from HEAD. Only the inert text of a name is removed: commands substituted into it
    ($(...) or `...`) run, so they are kept, with branch names inside them removed in turn.
    """
    parts, position = [], 0
    for start, end, substitutions in new_branch_names(text):
        parts.append(text[position:start])
        for inner_start, inner_end in substitutions:
            body = text[inner_start:inner_end]
            if _depth < MAX_SUBSTITUTION_DEPTH:
                body = without_new_branch_names(body, _depth + 1)
            parts.append(f" ; {body} ; ")
        position = end
    parts.append(text[position:])
    return "".join(parts)


_GIT = re.compile(r"\bgit(?=\s)", re.IGNORECASE)
# One word after optional blanks: quoted pieces and other characters, up to a blank or the end
# of the command. The alternatives start with different characters, so matching never backtracks.
_NEXT_WORD = re.compile(r"""[ \t]*((?:"[^"]*"?|'[^']*'?|[^\s;&|"'])+)""")
# How far after "git", in characters and in words, its subcommand is looked for. Fixed limits
# keep the cost of a line in proportion to its length however many times it says "git".
_SUBCOMMAND_WINDOW = 240
_SUBCOMMAND_WORDS = 8


def git_subcommands(line: str) -> list[tuple[str, int]]:
    """(subcommand, position after it) for each git command on a line, in lower case.

    Options between git and the subcommand are skipped, with their values: git -C dir fetch is
    fetch. After an option this reader does not know, the next word may be that option's value
    or the subcommand, so both it and the word after it are given. Text inside quotes is read
    too (bash -c "git fetch ..."), since a quoted command line is still a command line.
    """
    found = []
    for match in _GIT.finditer(line):
        limit = min(len(line), match.end() + _SUBCOMMAND_WINDOW)
        position, skip, maybe_value = match.end(), False, False
        for _ in range(_SUBCOMMAND_WORDS):
            next_word = _NEXT_WORD.match(line, position, limit)
            if next_word is None:
                break
            position = next_word.end()
            word = next_word.group(1).strip("\"'")
            if skip:
                skip = False
            elif word in _GIT_OPTIONS_WITH_VALUE:
                skip = True
            elif word.startswith("-"):
                maybe_value = word not in _GIT_FLAGS and "=" not in word
            else:
                found.append((word.lower(), position))
                if not maybe_value:
                    break
                maybe_value = False
    return found
