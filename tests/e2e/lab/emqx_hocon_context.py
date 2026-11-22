"""Private original-native-syntax occurrence ledger, never caller context claims.

Only the fixed native adapter is selected by the digest-verified owner. This
validator checks the complete multiplicity ledger before any dependency IO.
"""
from collections import Counter
from emqx_semantic_readers import _json_walk, _text, refuse
from emqx_republish_templates import _template, validate_action_reference

PROFILE = 'owner-pinned-image-vendor-acl-republish-context-v1'
CONTRACT = 'emqx-hocon-context-json-v1'


def register_syntax(document, result, literal):
    bindings = document['string_bindings']
    strings = document['syntax_strings']
    if type(bindings) is not list or len(bindings) > 8192:
        refuse()
    ledger = Counter(strings)
    for item in bindings:
        if type(item) is not dict or set(item) != {'path', 'role', 'value'}:
            refuse()
        path, role, value = item['path'], item['role'], item['value']
        if (type(value) is not str or type(path) is not list or not 0 < len(path) <= 32
                or any(type(p) not in (str, int) or (type(p) is int and p < 0) for p in path)
                or role not in ('key', 'value', 'republish-value', 'vendor-path', 'action-reference')):
            refuse()
        ledger[value] -= 1
        if ledger[value] < 0:
            refuse()
        result.tick(1)
        if role == 'action-reference':
            if (len(path) != 5 or path[:2] != ['rule_engine','rules']
                    or type(path[2]) is not str or not path[2]
                    or path[3] != 'actions' or type(path[4]) is not int):
                refuse()
            validate_action_reference(value, document['parsed'])
            _json_walk(value, result, 1)
        elif role == 'republish-value':
            if (len(path) != 7 or path[:2] != ['rule_engine', 'rules']
                    or type(path[2]) is not str or not path[2]
                    or path[3] != 'actions' or type(path[4]) is not int
                    or path[5] != 'args' or path[6] not in ('payload', 'topic', 'qos', 'retain')):
                refuse()
            # Plain qos/retain strings are rejected too, matching effective contract.
            _template(value, path[6], result)
        elif role == 'vendor-path':
            if (len(path) != 4 or path[:2] != ['authorization', 'sources']
                    or type(path[2]) is not int or path[3] != 'path' or value != literal):
                refuse()
            result.add(_text(value))
        else:
            _json_walk(value, result, 1)
    if any(ledger.values()):
        refuse()
    joined = document['concat_strings']
    if type(joined) is not list or len(joined)>8192 or any(type(s) is not str for s in joined):
        refuse()
    for value in joined:
        _json_walk(value, result, 1)
