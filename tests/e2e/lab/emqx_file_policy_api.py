"""Private FILE-target authorization proof; the builtin API 404 is never ACL proof.

FILE baseline target (emqx_real_owner_workflow._target_base/_target_acl) keeps the
target's whole authorization root (woowbackup.ha_emqx.preserved_settings) and, after
the guarded candidate-only builtin removal (woowbackup.ha_emqx_acl_preservation),
has NO built_in_database source. Pinned EMQX 5.8.9 then answers the builtin ACL REST
endpoints with an exact 404 (see emqx_source_api_validator constants). Three
independent proofs replace the old 200-inventory assumption, none uses the 404:

1. API collector: the exact vendor 404 on exactly the three builtin ACL endpoints,
   every other B1 endpoint/credential/identity contract unchanged, and the active
   FILE ACL read back by EMQX itself equal to the issued target policy bytes.
2. Native collector hook: the existing post-restore native capture (same fixed
   producer, wire and inventory validation) projects the emqx_acl table.
3. Comparator: that fresh capture, bound to the same owner/CID/identity/registry and
   strictly after the API result, must hold exactly the B1 source ACL inventory
   (who-set and per-who stored rule counts) that the strict API path requires.

Limits: rows are preserved but INACTIVE under the target file authorizer; this is
not source-ACL MQTT behavior, rule content equality or commercial acceptance. MQTT
probes of the active file ACL stay a separate mandatory workflow step.
"""
import copy
import weakref

from emqx_private_boundary import PrivateFailure

# emqx_authz_mnesia.erl:42-45 #emqx_acl{who = 0 | {1,Username} | {2,ClientId}, rules}
# (?ACL_TABLE_ALL/USERNAME/CLIENTID = 0/1/2, emqx_authz_mnesia.erl:27-29); stored rules
# are {Permission,Action,TopicFilter} (normalize_rule/1, emqx_authz_mnesia.erl:203-213)
# with Permission allow|deny (emqx_authz_rule_raw.erl:149-151). The API returns one
# formatted rule per stored rule (format_rules/1, emqx_authz_api_mnesia.erl:712-713).
ACL_WHO_KINDS = {0: 'all', 1: 'username', 2: 'clientid'}
ACL_PERMISSIONS = frozenset(('allow', 'deny'))
# Same fixed B1 expectation as the strict API facts: users b1-gateway:2/b1-sensor:2,
# clients b1-dashboard-panel:1, all:1 (emqx_source_api_validator._facts).
B1_NATIVE_ACL_INVENTORY = {('username', 'b1-gateway'): 2, ('username', 'b1-sensor'): 2,
                           ('clientid', 'b1-dashboard-panel'): 1, ('all', None): 1}

FILE_POLICY_ACL_STAGES = ('api', 'binding', 'order', 'table', 'row', 'inventory')
FILE_POLICY_ACL_PHASES = frozenset(('file_policy_acl',
                                    *('file_policy_acl_' + s for s in FILE_POLICY_ACL_STAGES)))

_FILE_POLICY_API = weakref.WeakKeyDictionary()
_NATIVE_ACL = weakref.WeakKeyDictionary()


class FilePolicyACLRefused(PrivateFailure):
    """Only a compiled stage label escapes."""
    def __init__(self, stage):
        self.phase = 'file_policy_acl_' + (stage if stage in FILE_POLICY_ACL_STAGES else 'api')
        super().__init__('file-policy-acl-refused')


class FilePolicyNativeACL:
    def __init__(self, api, native):
        self._api, self._native = api, native

    def __repr__(self):
        return '<EMQX private file-policy native ACL inventory>'

    def scan(self, payload):
        self._api.scan(payload)
        self._native.scan(payload)

    def scope(self):
        return ('native-emqx-acl-who-set-and-rule-counts-equal-b1-source',
                'inactive-under-target-file-authorizer-api404-not-used-as-proof',
                'not-active-source-acl-behavior-or-rule-content')


def validate_file_policy_source_api(*, target_file_acl, prior_registry, provision,
                                    expected_container_id, quiesce, port, admin_username,
                                    admin_password, second_username, second_password,
                                    api_key, api_secret, retained_topics):
    """Explicit FILE profile, same RAM inputs plus the issued target ACL bytes.

    Returns the ordinary private SourceAPIResult (bound by the same collector hook) so
    negative-MQTT/object/receipt consumers keep their checks; its facts carry no ACL
    fact and an explicit not-ACL-proof scope. Default validate_source_api stays strict.
    """
    from emqx_source_api_validator import (_observe_source_api, FILE_POLICY_API_PROFILE,
        FILE_POLICY_ACL_SCOPE, SourceAPIResult, SourceAPIPhaseRefused)
    result = _observe_source_api(api_profile=FILE_POLICY_API_PROFILE, target_file_acl=target_file_acl,
        prior_registry=prior_registry, provision=provision, expected_container_id=expected_container_id,
        quiesce=quiesce, port=port, admin_username=admin_username, admin_password=admin_password,
        second_username=second_username, second_password=second_password, api_key=api_key,
        api_secret=api_secret, retained_topics=retained_topics)
    try:
        if (type(result) is not SourceAPIResult or result in _FILE_POLICY_API
                or result._facts.get('acl_scope') != FILE_POLICY_ACL_SCOPE
                or any(name in result._facts for name in ('acl_users', 'acl_clients', 'acl_all'))):
            raise ValueError()
        _FILE_POLICY_API[result] = {'facts': copy.deepcopy(result._facts),
                                    'documents': copy.deepcopy(result._documents)}
    except Exception:
        raise SourceAPIPhaseRefused('proof', 'contract') from None
    return result


def _project_acl(tables):
    """Fixed classification of the already validated native emqx_acl rows; no IO."""
    from emqx_owner_target import _decode
    from emqx_semantic_readers import TABLES, Values
    record, attributes = TABLES['emqx_acl']
    matches = [t for t in tables if type(t) is dict and t.get('table') == 'emqx_acl']
    if (len(matches) != 1 or matches[0].get('record_name') != record
            or matches[0].get('attributes') != list(attributes) or type(matches[0].get('rows')) is not list):
        return ('table', None)
    inventory = {}
    for row in matches[0]['rows']:
        try:
            decoded = _decode(row, Values())
        except Exception:
            return ('row', None)
        if type(decoded) is not tuple or len(decoded) != 3 or decoded[0] != record:
            return ('row', None)
        who, rules = decoded[1], decoded[2]
        if type(who) is int and who == 0:
            key = ('all', None)
        elif (type(who) is tuple and len(who) == 2 and type(who[0]) is int and who[0] in (1, 2)
                and type(who[1]) is bytes and who[1]):
            try:
                key = (ACL_WHO_KINDS[who[0]], who[1].decode('utf-8'))
            except UnicodeError:
                return ('row', None)
        else:
            return ('row', None)
        if (type(rules) is not list or key in inventory
                or any(type(rule) is not tuple or len(rule) != 3 or type(rule[0]) is not str
                       or rule[0] not in ACL_PERMISSIONS for rule in rules)):
            return ('row', None)
        inventory[key] = len(rules)
    return ('ok', inventory)


def _record_native_acl(result, wire, generation):
    """Collector-only hook right AFTER emqx_native_object_integrity._record_native.

    Re-reads the same strictly validated wire. Projection problems are recorded as a
    fixed stage and never raise here, so other target modes keep their exact behavior;
    only the FILE comparator consumes the record.
    """
    from emqx_post_restore_values import PostRestoreValues
    if (type(result) is not PostRestoreValues or result in _NATIVE_ACL
            or result._persisted.generation != generation):
        raise ValueError()
    try:
        from emqx_owner_target import _read_reply
        _, doc = _read_reply(wire, generation)
        projection = _project_acl(doc['tables'])
    except Exception:
        projection = ('table', None)
    _NATIVE_ACL[result] = {'generation': generation, 'projection': projection}
    return result


def compare_file_policy_native_acl(*, source_api, native_values):
    """FILE-profile API result + fresh native capture of the SAME phase, or refuse.

    The API 404 contributes only the minted FILE observation binding; ACL equality is
    taken solely from the native emqx_acl inventory. Exact B1 who-set/rule counts.
    """
    stage = 'api'
    try:
        from emqx_source_api_validator import SourceAPIResult, FILE_POLICY_ACL_SCOPE
        from emqx_post_restore_values import PostRestoreValues
        from emqx_native_object_integrity import _API, _NATIVE, _root
        if type(source_api) is not SourceAPIResult or type(native_values) is not PostRestoreValues:
            raise ValueError()
        minted = _FILE_POLICY_API[source_api]
        if (source_api._facts != minted['facts'] or source_api._documents != minted['documents']
                or minted['facts'].get('acl_scope') != FILE_POLICY_ACL_SCOPE):
            raise ValueError()
        stage = 'binding'
        api, native, acl = _API[source_api], _NATIVE[native_values], _NATIVE_ACL[native_values]
        if (native['owner'] is not api[0] or native['cid'] != api[1] or native['identity'] != api[2]
                or native['registry'] is not api[3] or _root(source_api._prior) is not api[3]
                or _root(native_values) is not api[3] or native['persisted'] is not native_values._persisted
                or native['generation'] != native_values._persisted.generation
                or acl['generation'] != native['generation']):
            raise ValueError()
        stage = 'order'
        if native['order'] <= api[4]:
            raise ValueError()
        stage = 'binding'
        source_api.scan(b'')
        native_values.scan(b'')
        status, inventory = acl['projection']
        stage = status if status in ('table', 'row') else 'inventory'
        if status != 'ok' or inventory != B1_NATIVE_ACL_INVENTORY:
            raise ValueError()
        return FilePolicyNativeACL(source_api, native_values)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('file-policy-acl-cancelled') from None
    except Exception:
        raise FilePolicyACLRefused(stage) from None
