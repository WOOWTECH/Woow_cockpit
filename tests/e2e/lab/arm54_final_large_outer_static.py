"""Static reader of arm54_final_large_outer.py for the unit tests (the wrapper itself only runs on .54: importing
it would execute it). Returns the .deb digests the wrapper pins, parsed from its source with ast."""
import ast
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent / 'arm54_final_large_outer.py'


def wrapper_digests():
    tree = ast.parse(WRAPPER.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == 'DEBS' for t in node.targets):
            value = ast.literal_eval(node.value)
            return {name: row[0] for name, row in value.items()}
    raise LookupError('DEBS not found')
