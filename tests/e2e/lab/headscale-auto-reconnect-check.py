"""Validate two unchanged clients and both connected nodes; accepts synthetic JSON files only."""
import json
import sys


def check(nodes, pairs):
    if not isinstance(nodes, list) or len(nodes) != 2:
        return False
    if not all(isinstance(node, dict) and node.get('online') is True for node in nodes):
        return False
    node_ids = {str(node.get('id')) for node in nodes}
    client_ids = set()
    client_addresses = set()
    for before, after in pairs:
        if after.get('BackendState') != 'Running':
            return False
        a, b = before.get('Self') or {}, after.get('Self') or {}
        if any(not a.get(key) or a.get(key) != b.get(key) for key in ('ID', 'PublicKey', 'TailscaleIPs')):
            return False
        client_ids.add(str(b['ID']))
        client_addresses.add(frozenset(b['TailscaleIPs']))
    try:
        node_addresses = {frozenset(node['ip_addresses']) for node in nodes}
    except (KeyError, TypeError):
        return False
    # Stable client IDs differ from Headscale's numeric IDs; IP sets bind the
    # connected target nodes to the original two clients.
    return len(node_ids) == len(client_ids) == 2 and 'None' not in node_ids and node_addresses == client_addresses


if __name__ == '__main__':
    try:
        with open(sys.argv[1], encoding='utf-8') as handle:
            nodes = json.load(handle)
        pairs = []
        for i in (2, 4):
            with open(sys.argv[i], encoding='utf-8') as handle:
                before = json.load(handle)
            with open(sys.argv[i + 1], encoding='utf-8') as handle:
                after = json.load(handle)
            pairs.append((before, after))
        sys.exit(0 if check(nodes, pairs) else 1)
    except (OSError, ValueError, IndexError, TypeError):
        sys.exit(1)
