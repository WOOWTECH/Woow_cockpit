"""Strict, opt-in EMQX 5.8.9 builtin authorization reference classification.

For an explicitly decoded source object, not an entire authorization root.
This helper admits no other source types or reference-bearing fields.
Pinned native schema proof: emqx_builtin_authorizer_schema_fixture.escript.
"""
from .errors import BackupError


BUILTIN_SHAPES = frozenset(('exact_type_enable','exact_type_enable_maxrules100','unknown'))


def builtin_database_shape(source):
    """Diagnostic only, never admission: no values/keys are returned or logged."""
    if (type(source) is not dict or type(source.get('type')) is not str
            or source.get('type') != 'built_in_database'
            or type(source.get('enable')) is not bool):
        return 'unknown'
    if set(source) == {'type','enable'}:
        return 'exact_type_enable'
    if (set(source) == {'type','enable','max_rules'}
            and type(source['max_rules']) is int and source['max_rules'] == 100):
        return 'exact_type_enable_maxrules100'
    return 'unknown'


def builtin_database_references(source):
    """Validate explicit builtin bool enable, with optional typed max_rules=100.

    Exact two/three-key profiles only. Pinned 5.8.9 native schema declares 100;
    other positive integers may be native-valid but are NOT this restricted
    profile. Never fill defaults, strip fields, mutate the source or accept a
    custom loader/path. Caller preserves the full observed raw object/order.
    """
    if (type(source) is not dict
            or set(source) not in ({'type','enable'}, {'type','enable','max_rules'})
            or type(source['type']) is not str
            or source['type'] != 'built_in_database'
            or type(source['enable']) is not bool
            or ('max_rules' in source and (type(source['max_rules']) is not int or source['max_rules'] != 100))):
        raise BackupError('incompatible', 'EMQX 內建授權來源超出已核對的支援範圍。')
    return frozenset()
