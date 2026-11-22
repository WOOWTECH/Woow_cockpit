"""Private original-native-syntax occurrence ledger, never caller context claims.

Only the fixed native adapter is selected by the digest-verified owner. This
validator checks the complete multiplicity ledger before any dependency IO.
"""
from collections import Counter
from emqx_semantic_readers import _json_walk, _text, refuse
from emqx_republish_templates import _template, validate_action_reference, TemplateRefused, TEMPLATE_REASONS

PROFILE = 'owner-pinned-image-vendor-acl-republish-context-v1'
CONTRACT = 'emqx-hocon-context-json-v1'
HTTP_PROFILE = 'owner-pinned-image-vendor-acl-http-body-context-v1'
HTTP_CONTRACT = 'emqx-hocon-http-context-json-v1'
SQL_PROFILE = 'owner-pinned-image-vendor-acl-sql-alias-context-v1'
SQL_CONTRACT = 'emqx-hocon-sql-context-json-v1'

SYNTAX_PHASES = frozenset(('syntax_bindings','syntax_shape','syntax_multiplicity',
    'syntax_budget','syntax_http_binding','syntax_http_template','syntax_action_reference',
    'syntax_republish_context','syntax_republish_payload','syntax_republish_topic',
    'syntax_republish_qos','syntax_republish_retain','syntax_vendor_path',
    'syntax_key_literal','syntax_value_literal','syntax_concat_shape','syntax_concat_literal',
    *('syntax_republish_payload_'+reason for reason in TEMPLATE_REASONS)))


class SyntaxRefused(Exception):
    def __init__(self, phase):
        super().__init__('emqx-syntax-refused')
        self.phase = phase if type(phase) is str and phase in SYNTAX_PHASES else 'syntax_bindings'



def register_syntax(document, result, literal, *, profile=PROFILE):
    stage='syntax_bindings'
    try:
        bindings = document['string_bindings']
        per_binding, per_rule = {}, {}
        if profile == SQL_PROFILE:
            from emqx_sql_aliases import bound_aliases
            per_binding, per_rule = bound_aliases(document)
            for aliases in per_binding.values():
                for alias, source in aliases.items():
                    result.add(_text(alias))
                    for part in source:
                        result.add(_text(part))
        strings = document['syntax_strings']
        if type(bindings) is not list or len(bindings) > 8192:
            refuse()
        ledger = Counter(strings)
        for binding_index, item in enumerate(bindings):
            stage='syntax_shape'
            if type(item) is not dict or set(item) != {'path', 'role', 'value'}:
                refuse()
            path, role, value = item['path'], item['role'], item['value']
            if (type(value) is not str or type(path) is not list or not 0 < len(path) <= 32
                    or any(type(p) not in (str, int) or (type(p) is int and p < 0) for p in path)
                    or role not in (('key', 'value', 'republish-value', 'vendor-path', 'action-reference')
                                    + (('http-body-value',) if profile in (HTTP_PROFILE, SQL_PROFILE) else ()))):
                refuse()
            stage='syntax_multiplicity'
            ledger[value] -= 1
            if ledger[value] < 0:
                refuse()
            stage='syntax_budget'
            result.tick(1)
            if role == 'http-body-value':
                stage='syntax_http_binding'
                _http_body_binding(path, value, document['parsed'])
                stage='syntax_http_template'
                _template(value, 'payload', result)
            elif role == 'action-reference':
                stage='syntax_action_reference'
                if (len(path) != 5 or path[:2] != ['rule_engine','rules']
                        or type(path[2]) is not str or not path[2]
                        or path[3] != 'actions' or type(path[4]) is not int):
                    refuse()
                validate_action_reference(value, document['parsed'])
                _json_walk(value, result, 1)
            elif role == 'republish-value':
                stage='syntax_republish_context'
                if (len(path) != 7 or path[:2] != ['rule_engine', 'rules']
                        or type(path[2]) is not str or not path[2]
                        or path[3] != 'actions' or type(path[4]) is not int
                        or path[5] != 'args' or path[6] not in ('payload', 'topic', 'qos', 'retain')):
                    refuse()
                # Plain qos/retain strings are rejected too, matching effective contract.
                stage='syntax_republish_'+path[6]
                _template(value, path[6], result, _aliases=per_binding.get(binding_index))
            elif role == 'vendor-path':
                stage='syntax_vendor_path'
                if (len(path) != 4 or path[:2] != ['authorization', 'sources']
                        or type(path[2]) is not int or path[3] != 'path' or value != literal):
                    refuse()
                result.add(_text(value))
            else:
                stage='syntax_key_literal' if role == 'key' else 'syntax_value_literal'
                _json_walk(value, result, 1)
        stage='syntax_multiplicity'
        if any(ledger.values()):
            refuse()
        stage='syntax_concat_shape'
        joined = document['concat_strings']
        if type(joined) is not list or len(joined)>8192 or any(type(s) is not str for s in joined):
            refuse()
        for value in joined:
            stage='syntax_concat_literal'
            _json_walk(value, result, 1)
        return per_rule
    except TemplateRefused as error:
        if stage == 'syntax_republish_payload':
            stage += '_'+error.reason
        raise SyntaxRefused(stage) from None
    except Exception:
        raise SyntaxRefused(stage) from None


def _http_body_binding(path, value, document):
    if (len(path) != 5 or list(path[:2]) != ['actions','http']
            or type(path[2]) is not str or not path[2]
            or list(path[3:]) != ['parameters','body'] or type(value) is not str):
        refuse()
    validate_action_reference('http:' + path[2], document)


def validate_http_body(path, value, document, result):
    _http_body_binding(path, value, document)
    # HTTP's pinned formatter uses emqx_template + emqx_jsonish, as republish
    # payload does. This conservative common subset never renders/resolves.
    _template(value, 'payload', result)
