#!/usr/bin/env python3
"""Fixed-vocabulary checks for the real-HA Headscale lab run (services-a).

Every input is a small private JSON file inside the run's directory. Only fixed
PASS/FAIL lines and counts are printed: never node keys, machine keys, auth
keys, API keys, URLs with credentials or raw command output. The expected
values come from the b1 source summary (users, node ids/names/addresses/routes,
the real client's public identity, the server's public Noise key).
"""
import ipaddress
import json
import re
import sys
from pathlib import Path

MAX_JSON = 1024 * 1024
NODE_PUBLIC = re.compile(r'nodekey:[0-9a-f]{64}\Z')
MACHINE_PUBLIC = re.compile(r'mkey:[0-9a-f]{64}\Z')


class CheckError(Exception):
    pass


def require(ok, code):
    if not ok:
        raise CheckError(code)


def load(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'input_missing')
    data = path.read_bytes()
    require(len(data) <= MAX_JSON, 'input_too_large')
    return json.loads(data)


def _addresses(values):
    out = []
    for value in values or []:
        out.append(str(ipaddress.ip_address(value)))
    return sorted(out)


def server_nodes(nodes):
    """Normalise `headscale nodes list -o json` (0.29.x) rows to comparable tuples."""
    require(isinstance(nodes, list), 'nodes_not_list')
    rows = {}
    for node in nodes:
        require(isinstance(node, dict), 'node_not_object')
        node_id = int(node.get('id'))
        user = node.get('user') or {}
        rows[node_id] = {
            'given_name': node.get('given_name'),
            'user': user.get('name') if isinstance(user, dict) else None,
            'ip_addresses': _addresses(node.get('ip_addresses')),
            'online': node.get('online') is True,
            'node_key': node.get('node_key'),
            'approved_routes': sorted(node.get('approved_routes') or []),
        }
    return rows


def expected_nodes(expect):
    rows = {}
    for node in expect['nodes']:
        rows[int(node['id'])] = {'given_name': node['given_name'], 'user': node['user'],
                                 'ip_addresses': _addresses(node['ip_addresses']),
                                 'approved_routes': sorted(node.get('approved_routes') or [])}
    return rows


def check_nodes(expect, nodes, *, online=(), extra=0):
    """HA's nodes are all present with the same id/name/user/addresses/routes, nothing else except `extra`
    newly registered devices; `online` names node ids that must be connected."""
    found = server_nodes(nodes)
    want = expected_nodes(expect)
    require(len(found) == len(want) + extra, 'node_count_mismatch')
    for node_id, row in want.items():
        got = found.get(node_id)
        require(got is not None, 'ha_node_missing')
        for key in ('given_name', 'user', 'ip_addresses', 'approved_routes'):
            require(got[key] == row[key], 'ha_node_' + key + '_mismatch')
    for node_id in online:
        require(found[int(node_id)]['online'], 'node_not_online')
    return found


def check_users(expect, users):
    require(isinstance(users, list), 'users_not_list')
    got = sorted((int(u.get('id')), u.get('name')) for u in users if isinstance(u, dict))
    want = sorted((int(i), name) for i, name in expect['users'])
    require(got == want, 'users_mismatch')


def check_preauth(expect, keys):
    """HA's pre-auth keys moved (count, user, reusable/used flags); their plaintext is never compared here."""
    require(isinstance(keys, list), 'preauth_not_list')
    got = sorted((int(k.get('id')), bool(k.get('reusable')), bool(k.get('used'))) for k in keys if isinstance(k, dict))
    want = sorted((int(k['id']), bool(k.get('reusable')), bool(k.get('used'))) for k in expect['preauthkeys'])
    require(got == want, 'preauth_mismatch')


def check_client(expect, status):
    """The real client after the re-point: running, logged in, same node id, node key and addresses."""
    client = expect['client']
    require(isinstance(status, dict) and status.get('BackendState') == 'Running', 'client_not_running')
    require(not status.get('AuthURL'), 'client_needs_login')
    me = status.get('Self') or {}
    require(str(me.get('ID')) == str(client['NodeID']), 'client_node_id_changed')
    require(NODE_PUBLIC.fullmatch(str(client['NodePublicKey'])) is not None, 'expected_node_key_invalid')
    require(me.get('PublicKey') == client['NodePublicKey'], 'client_node_key_changed')
    require(_addresses(me.get('TailscaleIPs')) == _addresses(client['TailscaleIPs']), 'client_addresses_changed')
    require(me.get('HostName') == client['HostName'], 'client_hostname_changed')


def check_server_key(expect, document):
    """The control server's public Noise key (GET /key) is HA's: the identity moved."""
    want = str(expect['server_public_key'])
    require(MACHINE_PUBLIC.fullmatch(want) is not None, 'expected_server_key_invalid')
    require(isinstance(document, dict) and document.get('publicKey') == want, 'server_key_changed')


def check_records(expect, records):
    require(isinstance(records, list), 'records_not_list')
    got = sorted((r.get('name'), r.get('type'), r.get('value')) for r in records if isinstance(r, dict))
    want = sorted((r['name'], r['type'], r['value']) for r in expect['dns_extra_records'])
    require(got == want, 'dns_records_mismatch')


def main(argv):
    try:
        command, expect_path, *paths = argv
        expect = load(expect_path)
        if command == 'nodes':
            online = [x for x in (paths[1].split(',') if len(paths) > 1 and paths[1] else [])]
            extra = int(paths[2]) if len(paths) > 2 else 0
            check_nodes(expect, load(paths[0]), online=online, extra=extra)
            print(f'HA nodes present with ids, names, users, addresses and routes: PASS (online required: {len(online)}, '
                  f'new devices: {extra})')
        elif command == 'users':
            check_users(expect, load(paths[0]))
            print(f'HA users present with ids and names: PASS ({len(expect["users"])})')
        elif command == 'preauth':
            check_preauth(expect, load(paths[0]))
            print(f'HA pre-auth keys present (count and flags): PASS ({len(expect["preauthkeys"])})')
        elif command == 'client':
            check_client(expect, load(paths[0]))
            print('Real client kept node id, node key, addresses and hostname, logged in: PASS')
        elif command == 'server-key':
            check_server_key(expect, load(paths[0]))
            print('Control server public Noise key equals HA server key: PASS')
        elif command == 'records':
            check_records(expect, load(paths[0]))
            print(f'HA DNS extra records present: PASS ({len(expect["dns_extra_records"])})')
        else:
            raise CheckError('unknown_command')
    except CheckError as error:
        print(f'CHECK {argv[0] if argv else "?"}: FAIL {error}')
        return 1
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print(f'CHECK {argv[0] if argv else "?"}: FAIL invalid_input')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
