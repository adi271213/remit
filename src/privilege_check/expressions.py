"""Shared lexical boundary for supported GitHub expression property names.

This is not an expression evaluator. Hyphens belong to identifiers, so a
property such as inputs.use-secrets must never become a secrets context read.
"""

IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_-]*"
