"""Immutable ordinary generated EMQX R4 inputs; no IO, credentials or endpoints from the machine."""
from dataclasses import dataclass

IMAGE = 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b'
DUMMY_PASSWORD = 'r4-owned-example-password'
DUMMY_ENV = 'r4-owned-environment-value'
DUMMY_PSK = 'r4-owned-source-psk'
NODE = 'emqx@127.0.0.1'
SOURCE_ACL = (b'{allow, {username, "r4_source"}, all, ["r4/#"]}.\n'
              b'{allow, {username, "r4_target"}, all, ["woow/#"]}.\n{deny, all}.\n')
TARGET_ACL = b'{allow, {username, "r4_target"}, all, ["target/#"]}.\n{deny, all}.\n'


@dataclass(frozen=True)
class Case:
    id: str
    decision: str
    confirms: tuple = ()
    notices: tuple = ()
    expected: str = 'candidate-and-restart'


CASES = (
    Case('plain', 'D1', notices=('emqx.plain-passwords', 'emqx.clear-rows')),
    Case('dead_row', 'D1', notices=('emqx.clear-rows',)),
    Case('noauth', 'D5/S2', confirms=('emqx.no-authentication',)),
    Case('http_dummy', 'D4/S1', confirms=('emqx.external-authn', 'emqx.external-authz')),
    Case('file_dummy', 'D4/S1', confirms=('emqx.file-secret',)),
    Case('jq_constant', 'D4/S1', confirms=('emqx.jq-rule',)),
    Case('env_dummy', 'D4/S1', confirms=('emqx.jq-rule',)),
    Case('admin_public', 'D2/H3', notices=('emqx.default-dashboard',)),
    Case('changed_acl', 'D3', notices=('emqx.acl-replaced',)),
    Case('psk', 'E-43/R4', confirms=('emqx.device-psk',)),
    Case('lost_auth_setting', 'E-67/D0', expected='incompatible-before-packaging'),
)
BY_ID = {case.id: case for case in CASES}


def authn(algorithm='sha256', whose='source'):
    return [{'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True,
             'user_id_type': 'username', 'password_hash_algorithm': {'name': algorithm, 'salt_position': 'disable'},
             'bootstrap_file': '/fixture/' + whose + '.csv', 'bootstrap_type': 'plain'}]


def config(case_id, *, target=False):
    if case_id not in BY_ID:
        raise ValueError('unknown_generated_case')
    root = {'authentication': authn(whose='target' if target else 'source'),
            'authorization': {'no_match': 'deny', 'deny_action': 'ignore', 'sources': [
                {'type': 'file', 'enable': True, 'path': 'data/authz/acl.conf'}]},
            'plugins': {'states': []}, 'log': {'console': {'level': 'error'}}}
    if target:
        # Built-in source is absent in HA; candidate must disable before removing it without erasing HA ACL rows.
        root['authorization']['sources'].insert(0, {'type': 'built_in_database', 'enable': True})
        if case_id == 'psk':
            root['psk_authentication'] = {'enable': True, 'init_file': '/fixture/target.psk', 'separator': ':'}
        return root
    if case_id in ('plain', 'dead_row'):
        root['authentication'] = authn('plain')
    if case_id == 'noauth':
        root['authentication'] = []
    if case_id in ('http_dummy', 'lost_auth_setting'):
        root['authentication'] = [{'mechanism': 'password_based', 'backend': 'http', 'enable': True,
            'method': 'get', 'url': 'http://127.0.0.1:18091/authn',
            'body': {'username': '${username}', 'password': '${password}'}, 'headers': {}}]
        if case_id == 'http_dummy':
            root['authorization']['sources'].insert(0, {'type': 'http', 'enable': True, 'method': 'get',
                'url': 'http://127.0.0.1:18091/authz', 'body': {'username': '${username}', 'topic': '${topic}'},
                'headers': {}})
    if case_id == 'file_dummy':
        root['connectors'] = {'mqtt': {'r4_dummy': {'enable': True, 'server': '127.0.0.1:1883',
            'proto_ver': 'v4', 'username': 'r4_dummy', 'password': 'file:///fixture/file-dummy.txt',
            'pool_size': 1, 'clean_start': True}}}
    if case_id in ('jq_constant', 'env_dummy'):
        query = '.fixture' if case_id == 'jq_constant' else 'env.WOOW_R4_DUMMY'
        root['rule_engine'] = {'rules': {'r4_jq': {'enable': True,
            'sql': "SELECT jq('" + query + "', payload) AS fixture FROM \"r4/jq\"", 'actions': []}}}
    if case_id == 'psk':
        root['psk_authentication'] = {'enable': True, 'init_file': '/fixture/source.psk', 'separator': ':'}
    return root


def files():
    # These are all fixture file contents. No caller supplies a host path or credential value.
    header = 'user_id,password,is_superuser\n'
    return {'source.csv': (header + 'r4_source,' + DUMMY_PASSWORD + ',false\nr4_dummy,' + DUMMY_PASSWORD + ',false\n').encode(),
            'target.csv': (header + 'r4_target,r4-owned-target-password,false\n').encode(),
            'file-dummy.txt': DUMMY_PASSWORD.encode(),
            'source.psk': ('r4_shared:' + DUMMY_PSK + '\n').encode(),
            'target.psk': b'r4_shared:r4-owned-target-psk\n',
            'dummy.env': ('WOOW_R4_DUMMY=' + DUMMY_ENV + '\n').encode()}


def dead_row_update():
    """A normal hashing setting change after plain bootstrap; no invented Mnesia/backup rows."""
    return {'authentication': authn('sha256')}


def addon_options():
    # Current product explicitly reports options/env_vars not moved. This is recorded current policy,
    # NOT a successful native case implemented by passing an env-file around the product reader.
    return {'env_vars': [{'name': 'EMQX_AUTHORIZATION__NO_MATCH', 'value': 'allow'}]}


def matrix():
    return [dict(id=c.id, decision=c.decision, expected=c.expected, confirms=list(c.confirms),
                 notices=list(c.notices), smoke='requires-separate-owned-package-device') for c in CASES]
