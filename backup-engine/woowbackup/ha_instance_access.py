"""N8-01/L-03 data-object access, never SQL/programs supplied by HA.

Only these converters' application schemas move. In particular LiteLLM L-38's deliberately omitted schemas are
neither recreated nor granted back. All SQL below is fixed grammar with quoted catalog identifiers/literals.
"""
import re
import json

SCHEMAS = {'n8n': ('public',), 'litellm': ('public', 'woow_platform')}
PRIVILEGES = {'database': {'CONNECT', 'CREATE', 'TEMPORARY'}, 'schema': {'USAGE', 'CREATE'},
              'r': {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'},
              'p': {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'},
              'S': {'SELECT', 'UPDATE', 'USAGE'}, 'column': {'SELECT', 'INSERT', 'UPDATE', 'REFERENCES'}}
CONTROL_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.+-]{0,62}\Z')


def ident(value):
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def _name(value):
    return isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 63 and all(ord(c) >= 32 for c in value)


def validate(plan, app_id):
    """Bounded structured facts; no source SQL, routine definitions or arbitrary schemas can enter the plan."""
    def need(ok):
        if not ok:
            raise ValueError('invalid HA instance access')
    def acl(rows, kind):
        need(isinstance(rows, list) and len(rows) <= 4096)
        seen = set()
        for row in rows:
            need(isinstance(row, list) and len(row) == 3)
            role, privilege, grantable = row
            need(role is None or _name(role))
            need(isinstance(privilege, str) and privilege in PRIVILEGES[kind] and type(grantable) is bool)
            need((role, privilege) not in seen)
            seen.add((role, privilege))
    need(app_id in SCHEMAS and isinstance(plan, dict) and
         set(plan) == {'database', 'schemas', 'relations', 'columns', 'extensions'})
    need(len(json.dumps(plan, ensure_ascii=True)) <= 1024 * 1024)
    need(isinstance(plan['database'], list) and len(plan['database']) == 2 and _name(plan['database'][0]))
    acl(plan['database'][1], 'database')
    for key, limit in (('schemas', 2), ('relations', 10000), ('columns', 10000), ('extensions', 100)):
        need(isinstance(plan[key], list) and len(plan[key]) <= limit)
    schemas = set()
    for row in plan['schemas']:
        need(isinstance(row, list) and len(row) == 3)
        name, owner, grants = row
        need(name in SCHEMAS[app_id] and name not in schemas and _name(owner))
        schemas.add(name)
        acl(grants, 'schema')
    objects = set()
    for row in plan['relations']:
        need(isinstance(row, list) and len(row) == 5)
        schema, name, kind, owner, grants = row
        need(schema in schemas and _name(name) and kind in ('r', 'p', 'S') and _name(owner))
        need((schema, name) not in objects)
        objects.add((schema, name))
        acl(grants, kind)
    columns = set()
    for row in plan['columns']:
        need(isinstance(row, list) and len(row) == 4)
        schema, table, column, grants = row
        need((schema, table) in objects and _name(column) and (schema, table, column) not in columns)
        columns.add((schema, table, column))
        acl(grants, 'column')
    extensions = set()
    for row in plan['extensions']:
        need(isinstance(row, list) and len(row) == 3 and all(isinstance(v, str) for v in row))
        name, version, schema = row
        need(CONTROL_NAME.fullmatch(name) and CONTROL_NAME.fullmatch(version) and schema in schemas)
        need(name != 'plpgsql' and name not in extensions)
        extensions.add(name)
    return plan


def _acl(value, owner, kind):
    return ("(SELECT coalesce(json_agg(json_build_array(CASE WHEN a.grantee=0 THEN NULL ELSE "
            "pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable) ORDER BY a.grantee,a.privilege_type),"
            f"'[]'::json) FROM aclexplode(coalesce({value},acldefault(({kind})::\"char\",{owner}))) a)")


def capture_sql(app_id):
    schemas = ','.join(literal(s) for s in SCHEMAS[app_id])
    return ("SELECT json_build_object('database',(SELECT json_build_array(pg_get_userbyid(d.datdba)," +
            _acl('d.datacl', 'd.datdba', "'d'") + ") FROM pg_database d WHERE datname=current_database()),"
            "'schemas',(SELECT coalesce(json_agg(json_build_array(n.nspname,pg_get_userbyid(n.nspowner)," +
            _acl('n.nspacl', 'n.nspowner', "'n'") + f") ORDER BY n.nspname),'[]'::json) FROM pg_namespace n "
            f"WHERE n.nspname IN ({schemas})),'relations',(SELECT coalesce(json_agg(json_build_array(n.nspname,"
            "c.relname,c.relkind,pg_get_userbyid(c.relowner)," +
            _acl('c.relacl', 'c.relowner', "CASE WHEN c.relkind='S' THEN 's' ELSE 'r' END") +
            ") ORDER BY n.nspname,c.relname),'[]'::json) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            f"WHERE n.nspname IN ({schemas}) AND c.relkind IN ('r','p','S') AND NOT EXISTS "
            "(SELECT 1 FROM pg_depend x WHERE x.classid='pg_class'::regclass AND x.objid=c.oid AND x.deptype='e')),"
            "'columns',(SELECT coalesce(json_agg(json_build_array(n.nspname,c.relname,a.attname," +
            _acl('a.attacl', 'c.relowner', "'c'") + ") ORDER BY n.nspname,c.relname,a.attname),'[]'::json) "
            "FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
            f"WHERE n.nspname IN ({schemas}) AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped "
            "AND a.attacl IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_depend x WHERE x.classid='pg_class'::regclass "
            "AND x.objid=c.oid AND x.deptype='e')),'extensions',(SELECT coalesce(json_agg(json_build_array(e.extname,e.extversion,n.nspname) ORDER BY "
            "e.extname),'[]'::json) FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace "
            f"WHERE e.extname<>'plpgsql' AND n.nspname IN ({schemas})))")


def permissions(target, owner, grants, kind, column=None):
    """Exact direct privileges, including PUBLIC revocation and grant options, assigned by the actual owner."""
    roles = {row[0] for row in grants} | {None, owner}
    grantee = lambda role: 'PUBLIC' if role is None else ident(role)
    suffix = ' (' + ident(column) + ')' if column is not None else ''
    result = [f'REVOKE ALL{suffix} ON {target} FROM {grantee(role)};' for role in sorted(roles, key=lambda r: r or '')]
    result.append(f'SET LOCAL ROLE {ident(owner)};')
    result += [f'GRANT {privilege}{suffix} ON {target} TO {grantee(role)}' +
               (' WITH GRANT OPTION' if grantable else '') + ';' for role, privilege, grantable in grants]
    result.append('RESET ROLE;')
    return result


def restore_sql(plan, present, database):
    """Only intersecting data objects: omitted schemas/tables and every program stay omitted."""
    result = permissions('DATABASE ' + ident(database), plan['database'][0], plan['database'][1], 'database')
    schemas = {row[0] for row in present['schemas']}
    relations = {(row[0], row[1], row[2]) for row in present['relations']}
    for schema, owner, grants in plan['schemas']:
        if schema in schemas:
            result.append(f'ALTER SCHEMA {ident(schema)} OWNER TO {ident(owner)};')
            result += permissions('SCHEMA ' + ident(schema), owner, grants, 'schema')
    # Tables before their owned sequences: PostgreSQL requires a sequence's owner to match its table's owner.
    for schema, name, kind, owner, grants in sorted(plan['relations'], key=lambda r: r[2] == 'S'):
        if (schema, name, kind) in relations:
            target = ('SEQUENCE ' if kind == 'S' else 'TABLE ') + ident(schema) + '.' + ident(name)
            result.append(f'ALTER {target} OWNER TO {ident(owner)};')
            result += permissions(target, owner, grants, kind)
    owners = {(r[0], r[1]): r[-2] for r in plan['relations']}
    for schema, table, column, grants in plan['columns']:
        if any(r[:2] == [schema, table] for r in present['relations']):
            result += permissions('TABLE ' + ident(schema) + '.' + ident(table), owners[schema, table],
                                  grants, 'column', column)
    return '\n'.join(result) + '\n'


def comparable(plan, present):
    """Normalize ACL order and restrict comparison to moved objects, never L-38's deliberately omitted ones."""
    schemas = {r[0] for r in present['schemas']}
    relations = {(r[0], r[1], r[2]) for r in present['relations']}
    normalize = lambda row: row[:-1] + [sorted(row[-1], key=lambda g: (g[0] or '', g[1], g[2]))]
    return {'database': normalize(plan['database']),
            'schemas': [normalize(r) for r in plan['schemas'] if r[0] in schemas],
            'relations': [normalize(r) for r in plan['relations'] if tuple(r[:3]) in relations],
            'columns': [normalize(r) for r in plan['columns'] if any(p[:2] == r[:2] for p in present['relations'])],
            'extensions': plan['extensions']}
