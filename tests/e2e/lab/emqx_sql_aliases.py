"""Private native SQL witnesses attached to ORIGINAL template occurrences.

No SQL, function or action evaluation; no caller alias overrides. Real owner
selects only the fixed native adapter after verified source digest binding.
"""
import hashlib
from emqx_semantic_readers import refuse
from emqx_republish_templates import _alias_source, _ALIAS_NAME, _ALIAS_RESERVED, _SCALAR_ROOTS, _MAP_ROOTS


def bound_aliases(document):
    witnesses = document['alias_bindings']
    bindings = document['string_bindings']
    if type(witnesses) is not list or len(witnesses)>8192 or type(bindings) is not list:
        refuse()
    per_binding, per_rule = {}, {}
    for witness in witnesses:
        if type(witness) is not dict or set(witness)!={'binding_index','rule_path','sql_sha256','aliases'}:
            refuse()
        index, path = witness['binding_index'], witness['rule_path']
        if (type(index) is not int or not 0<=index<len(bindings) or index in per_binding
                or type(path) is not list or len(path)!=3 or path[:2]!=['rule_engine','rules']
                or type(path[2]) is not str or not path[2]):
            refuse()
        binding=bindings[index]
        if (type(binding) is not dict or binding.get('role')!='republish-value'
                or type(binding.get('path')) is not list or len(binding['path'])!=7
                or binding['path'][:3]!=path or binding['path'][3]!='actions'
                or type(binding['path'][4]) is not int or binding['path'][4]<0
                or binding['path'][5]!='args' or binding['path'][6] not in ('payload','topic','qos','retain')):
            refuse()
        parsed=document['parsed']
        rules=parsed.get('rule_engine',{}).get('rules',{})
        rule=rules.get(path[2])
        if type(rule) is not dict or type(rule.get('sql')) is not str:
            refuse()
        sql=rule['sql'].encode('utf-8')
        if not sql or len(sql)>65536 or witness['sql_sha256']!=hashlib.sha256(sql).hexdigest():
            refuse()
        aliases=witness['aliases']
        if type(aliases) is not dict or not 0<len(aliases)<=64:
            refuse()
        for name, source in aliases.items():
            if (type(name) is not str or not _ALIAS_NAME.fullmatch(name)
                    or name.lower() in _ALIAS_RESERVED or name in _SCALAR_ROOTS|_MAP_ROOTS):
                refuse()
            _alias_source(source)
        if path[2] in per_rule and per_rule[path[2]]!=aliases:
            refuse()
        per_binding[index]=aliases
        per_rule[path[2]]=aliases
    return per_binding, per_rule
