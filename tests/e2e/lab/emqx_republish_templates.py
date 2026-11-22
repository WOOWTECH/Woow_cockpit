"""Opt-in private effective rule-engine values; not a complete source reader.

Only message-data placeholders in declared builtin republish actions are data.
No template is rendered, no bindings/messages are loaded, no environment/file/
vault/include is resolved. Default HOCON/source/vendor readers are unchanged.
The caller must still account for native historical syntax with actual context;
flat syntax_strings equality is NOT permission to bypass that separate gate.
"""
import json
import re

from emqx_semantic_readers import Values, MAX_DEPTH, _json_walk, _text, refuse, SemanticRefused

PROFILE = 'owner-rule-engine-republish-message-v1'
_FIELDS = frozenset(('payload', 'topic', 'qos', 'retain'))
_SCALARS = frozenset(('topic', 'clientid', 'username', 'qos', 'retain', 'flags.retain'))
# Conservative subset of public emqx_template's ASCII dotted map accessor.
# Numeric segments are map keys, NOT an invented array-index evaluator.
_PLACEHOLDER = re.compile(r'\$\{(\.?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*|\.)\}')


TEMPLATE_REASONS = frozenset(('size','budget','escape','loader','grammar',
                                  'unknown_root','depth','field_contract'))


class TemplateRefused(SemanticRefused):
    def __init__(self, reason):
        super().__init__()
        self.reason = reason if type(reason) is str and reason in TEMPLATE_REASONS else 'grammar'


def _template(value, field, result):
    stage='size'
    try:
        raw = _text(value)
        stage='budget'
        result.add(raw)  # Full source literal always remains private.
        if '$${' in value:
            raise TemplateRefused('escape')
        if any(scheme in value.lower() for scheme in ('file:', 'env:', 'vault:')):
            raise TemplateRefused('loader')
        matches = []
        position = 0
        while True:
            start = value.find('${', position)
            if start < 0:
                result.add(value[position:].encode())
                break
            result.add(value[position:start].encode())
            match = _PLACEHOLDER.match(value, start)
            if match is None:
                raise TemplateRefused('grammar')
            name = match.group(1)
            parts = name.removeprefix('.').split('.')
            if name == '.':
                if field != 'payload':
                    raise TemplateRefused('field_contract')
            else:
                if len(parts) > MAX_DEPTH:
                    raise TemplateRefused('depth')
                if not (parts[0] == 'payload' or '.'.join(parts) in _SCALARS):
                    raise TemplateRefused('unknown_root')
            result.add(match.group().encode())
            result.add(name.encode())
            for part in parts:
                result.add(part.encode())
            matches.append(match.span())
            position = match.end()
        # Runtime parse_simple_var/render_simple_var expects one placeholder only.
        if field in ('qos', 'retain') and matches != [(0, len(value))]:
            raise TemplateRefused('field_contract')
    except TemplateRefused:
        raise
    except Exception:
        raise TemplateRefused(stage) from None


def validate_action_reference(value, document):
    """Literal HTTP action ID bound to the SAME native document, never executed."""
    if type(value) is not str or not re.fullmatch(r'http:[A-Za-z0-9_-]+', value):
        refuse()
    if type(document) is not dict:
        refuse()
    actions = document.get('actions')
    http = actions.get('http') if type(actions) is dict else None
    action = http.get(value.split(':', 1)[1]) if type(http) is dict else None
    connector = action.get('connector') if type(action) is dict else None
    if type(connector) is not str or not re.fullmatch(r'[A-Za-z0-9_-]+', connector):
        refuse()
    connectors = document.get('connectors')
    http_connectors = connectors.get('http') if type(connectors) is dict else None
    if (type(http_connectors) is not dict or type(http_connectors.get(connector)) is not dict
            or not http_connectors[connector]):
        refuse()


def collect_rule_engine_values(rule_engine, *, profile=None, document=None):
    """Collect a native parsed rule_engine subtree, with exact action context.

    Known message roots: payload (dotted map fields), topic, clientid, username,
    qos, retain, flags.retain; payload also accepts the whole-message `${.}`.
    No selected SQL aliases, custom functions, escapes/brackets/calls are inferred.
    This returns private Values only: no Registry seal/coverage/replay capability.
    It covers the effective subtree, not unlocated overwritten/concat syntax.
    """
    try:
        if profile != PROFILE or type(rule_engine) is not dict:
            refuse()
        result = Values()

        def action_field(location):
            if (len(location) != 7 or location[:2] != ('rule_engine', 'rules')
                    or type(location[2]) is not str or not location[2]
                    or location[3] != 'actions' or type(location[4]) is not int
                    or location[4] < 0 or location[5] != 'args' or location[6] not in _FIELDS):
                return None
            rules = rule_engine.get('rules')
            rule = rules.get(location[2]) if type(rules) is dict else None
            actions = rule.get('actions') if type(rule) is dict else None
            if type(actions) is not list or location[4] >= len(actions):
                return None
            action = actions[location[4]]
            if type(action) is not dict or action.get('function') != 'republish':
                return None
            return location[6]

        def walk(value, location, depth):
            if location == ('rule_engine', 'rules') and type(value) is not dict:
                refuse()
            if len(location) == 3 and location[:2] == ('rule_engine', 'rules'):
                if type(location[2]) is not str or not location[2] or type(value) is not dict:
                    refuse()
            if (len(location) == 4 and location[:2] == ('rule_engine', 'rules')
                    and location[3] == 'actions' and type(value) is not list):
                refuse()
            if (len(location) == 5 and location[:2] == ('rule_engine', 'rules')
                    and location[3] == 'actions'):
                if type(value) is str:
                    if type(document) is not dict or document.get('rule_engine') is not rule_engine:
                        refuse()
                    validate_action_reference(value, document)
                    _json_walk(value, result, depth)
                    return
                if (type(value) is not dict or value.get('function') != 'republish'
                        or type(value.get('args')) is not dict):
                    refuse()
            if action_field(location) is not None and type(value) in (dict, list):
                refuse()
            if type(value) is dict:
                result.tick(depth)
                if value.get('type') == 'file':
                    refuse()
                for key, child in value.items():
                    _json_walk(key, result, depth + 1)
                    if (key in ('certfile', 'keyfile', 'cacertfile', 'bootstrap_file', 'init_file')
                            or key.endswith('_file')) and child:
                        refuse()
                    walk(child, location + (key,), depth + 1)
            elif type(value) is list:
                result.tick(depth)
                for index, child in enumerate(value):
                    walk(child, location + (index,), depth + 1)
            else:
                field = action_field(location)
                if type(value) is str and any(s in value.lower() for s in ('file:', 'env:', 'vault:')):
                    refuse()
                if field is not None:
                    result.tick(depth)
                    if field in ('payload', 'topic') and type(value) is str:
                        _template(value, field, result)
                        return
                    if field in ('qos', 'retain') and type(value) is str:
                        _template(value, field, result)
                        return
                    if field == 'qos' and type(value) is int and value in (0, 1, 2):
                        result.add(str(value).encode())
                        return
                    if field == 'retain' and type(value) is bool:
                        result.add(b'true' if value else b'false')
                        return
                    refuse()
                _json_walk(value, result, depth)
                if value is None or type(value) in (bool, int, float):
                    result.add(json.dumps(value, allow_nan=False).encode())

        walk(rule_engine, ('rule_engine',), 1)
        return result
    except Exception:
        raise SemanticRefused() from None
