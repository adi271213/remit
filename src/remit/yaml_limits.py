"""Bound the entire composed YAML graph before constructing Python objects."""
import yaml

MAX_ALIASES = 500
MAX_EXPANDED_NODES = 200_000
MAX_EXPANDED_SCALAR_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_DEPTH = 50


def validate_graph(root):
    # Composition shares aliased nodes. Memoize costs, but charge each reference
    # its full logical subtree cost, including aliases in otherwise unused data.
    # This protects all downstream consumers, not just expression extraction.
    costs = {}
    active = set()

    def visit(node):
        identity = id(node)
        if identity in active:
            raise ValueError("Recursive YAML aliases are unsupported.")
        if identity in costs:
            return costs[identity]
        if len(active) >= MAX_EXPANDED_DEPTH:
            raise ValueError("Expanded YAML exceeds depth limit.")
        active.add(identity)
        nodes, scalar_bytes, height = 1, 0, 1
        if isinstance(node, yaml.nodes.ScalarNode):
            scalar_bytes = len(node.value.encode("utf-8"))
            children = ()
        elif isinstance(node, yaml.nodes.SequenceNode):
            children = node.value
        elif isinstance(node, yaml.nodes.MappingNode):
            children = (child for pair in node.value for child in pair)
        else:
            raise ValueError("Unsupported YAML node.")
        for child in children:
            child_nodes, child_bytes, child_height = visit(child)
            nodes += child_nodes
            scalar_bytes += child_bytes
            height = max(height, child_height + 1)
            if nodes > MAX_EXPANDED_NODES or scalar_bytes > MAX_EXPANDED_SCALAR_BYTES:
                raise ValueError("Expanded YAML exceeds node or scalar-byte limit.")
            if height > MAX_EXPANDED_DEPTH:
                raise ValueError("Expanded YAML exceeds depth limit.")
        if nodes > MAX_EXPANDED_NODES or scalar_bytes > MAX_EXPANDED_SCALAR_BYTES:
            raise ValueError("Expanded YAML exceeds node or scalar-byte limit.")
        active.remove(identity)
        costs[identity] = nodes, scalar_bytes, height
        return costs[identity]

    if root is not None:
        visit(root)
