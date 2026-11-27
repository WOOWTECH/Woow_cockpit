#!/usr/bin/env python3
"""Prints the mutant ids of the sweep (mutations.py) in chunks: chunks.py N -> one comma separated line per chunk (the two controls go with the first)."""
import ast, sys
src = open('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/parity-odoo/mutations.py', encoding='utf-8').read()
tree = ast.parse(src)
def listed(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == name)
    return [m[0] for m in ast.literal_eval(node.value)]
ids, controls = listed('MUTATIONS'), listed('CONTROLS')
size = int(sys.argv[1])
chunks = [ids[i:i + size] for i in range(0, len(ids), size)]
chunks[0] += controls
for chunk in chunks:
    print(','.join(chunk))
