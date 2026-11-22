"""Strict, opt-in EMQX 5.8.9 builtin authorization reference classification.

For an explicitly decoded source object, not an entire authorization root.
This helper does not admit other sources or alter the main FILE-only guard.
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
    """Validate exactly {type: built_in_database, enable: bool}; no file refs.

    Require explicit enable even though native schema has defaults. Unknown keys
    (including native max_rules), cooked-default expansion, loaders and paths are
    outside this deliberately restricted profile. Disabled sources are checked
    just as strictly as enabled ones. This proves no source-level file reference,
    not completeness of persistent ACL rows, global policy or runtime behavior.
    Caller must preserve source order and check every other source independently.
    """
    if (type(source) is not dict or set(source) != {'type', 'enable'}
            or type(source['type']) is not str
            or source['type'] != 'built_in_database'
            or type(source['enable']) is not bool):
        raise BackupError('incompatible', 'EMQX 內建授權來源超出已核對的支援範圍。')
    return frozenset()
