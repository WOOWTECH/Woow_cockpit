"""Built-in data verification digests (CONTRACT sections 4, 5 and 9). Owner: E2 engine core.

Two kinds of check need no help from the application:

* `files-digest` (a volume or a host directory): the owner-side helper (`podman.DIR_HELPER digest|digestvol`) lists every
  entry as seen inside the owner's user namespace, one line each, sorted by path bytes:
  `<kind> <mode> <uid> <gid> <size> <sha256|-> <link target hex|-> <path hex>` (kind f d l p c b; sockets are not
  listed, tar never keeps them).
* `postgres-digest`: per-table row counts and order-independent content digests read with psql (and, for a whole
  instance, the roles and memberships), turned here into lines `D <db>` (every database read, also an empty one),
  `T <db> <schema> <table> <r|S> <rows> <a> <b>`,
  `R <role> <flags> <connection limit> <valid until|-> <md5 of the password hash|->` and `M <role> <member> <t|f>`
  (names hex-encoded UTF-8), sorted.

The digest of a check is the sha256 of its lines. They are captured while every writer is stopped (backup) and again
after a restore before the app's units start, so a match is exact. Everything the owner side printed is untrusted:
it is parsed line by line, checked to be strictly sorted, bounded, and the digest is recomputed here.
"""
import hashlib
import json
import re

from .errors import BackupError

MAX_ENTRIES = 2000000            # same cap as a volume or directory tar (woowbackup.nested)
MAX_LINE = 20000
SAMPLES = 20                      # differences named in a job result
FILE_LINE_RE = re.compile(rb'([fdlpcb]) ([0-7]{4}) ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,20}) ([0-9a-f]{64}|-) '
                          rb'((?:[0-9a-f]{2}){1,4096}|-) ((?:[0-9a-f]{2}){1,4096})\n\Z')
PG_LINE_RE = re.compile(rb'(?:D ((?:[0-9a-f]{2}){1,512})'
                        rb'|T ((?:[0-9a-f]{2}){1,512}) ((?:[0-9a-f]{2}){1,512}) ((?:[0-9a-f]{2}){1,512}) ([rS]) '
                        rb'([0-9]{1,20}) (-?[0-9]{1,40}) (-?[0-9]{1,40})'
                        rb'|R ((?:[0-9a-f]{2}){1,512}) ([tf]{7}) (-?[0-9]{1,10}) ((?:[0-9a-f]{2}){1,200}|-) ([0-9a-f]{32}|-)'
                        rb'|M ((?:[0-9a-f]{2}){1,512}) ((?:[0-9a-f]{2}){1,512}) ([tf]))\n\Z')
FILE_KINDS = {'f': '檔案', 'd': '資料夾', 'l': '符號連結', 'p': 'FIFO', 'c': '字元裝置', 'b': '區塊裝置'}
SUMMARY_KEYS = {'files-digest': ('entries', 'files', 'dirs', 'symlinks', 'other', 'bytes'),
                'postgres-digest': ('databases', 'tables', 'sequences', 'rows', 'roles')}
SUMMARY_LABELS = {'entries': '項目', 'files': '檔案', 'dirs': '資料夾', 'symlinks': '符號連結', 'other': '其他',
                  'bytes': '位元組', 'databases': '資料庫', 'tables': '資料表', 'sequences': '序列', 'rows': '資料列',
                  'roles': '角色'}
# psql session settings that make a row's text independent of the server's and the client's defaults (lc_monetary:
# `money` columns; review L4). Every digest psql call also sets PGCLIENTENCODING=UTF8 (names of a LATIN1 database
# arrive as UTF-8; review F6).
PG_OPTIONS = ('-c TimeZone=UTC -c DateStyle=ISO,YMD -c IntervalStyle=postgres -c extra_float_digits=1 '
              '-c bytea_output=hex -c search_path=pg_catalog -c standard_conforming_strings=on -c lc_monetary=C')
# Before PostgreSQL 12, extra_float_digits=1 printed float values with 17 significant digits; 12 and later print the
# shortest exact form. A digest read on 11 or older is therefore not compared with one read on 12 or newer.
FLOAT_TEXT_MAJOR = 12

# A row's text is `record_out(t.*)`: the row type's own output function. `t::text` ran a cast a table owner can define
# (CREATE CAST (tbl AS text) WITH FUNCTION ...) as the digest's superuser, and resolved to a column named `t` instead
# of the whole row (review H1, F2); both give the same text for every other table. A SQL_ASCII database hashes its
# bytes as stored (they need not be UTF-8; review F6), every other database the UTF-8 text.
_ROW = ("SELECT count(*) AS c, coalesce(sum(('x'||substr(h,1,16))::bit(64)::bigint),0) AS a, "
        "coalesce(sum(('x'||substr(h,17,16))::bit(64)::bigint),0) AS b FROM (SELECT md5(convert_to({value}, "
        "CASE WHEN pg_catalog.getdatabaseencoding() = 'SQL_ASCII' THEN 'SQL_ASCII' ELSE 'UTF8' END)) "
        "AS h FROM %I.%I t) s")
ROW_TEXT = 'pg_catalog.record_out(t.*)::text'
_TABLE = _ROW.format(value=ROW_TEXT).replace("'", "''")
# Sequences: only what a restore sets (setval); log_cnt is internal state.
_SEQUENCE = _ROW.format(value="t.last_value::text||':'||t.is_called::text").replace("'", "''")
# Every ordinary table and sequence outside the system schemas, temporary relations and extension members; one row
# per relation [schema, name, kind, rows, a, b] where a and b are sums of 64-bit halves of each row's md5 (order of
# the rows does not matter, duplicates count). Run once per database.
TABLES_SQL = (
    "SELECT coalesce(json_agg(json_build_array(r.nspname, r.relname, r.relkind, (xpath('/row/c/text()', r.x))[1]::text, "
    "(xpath('/row/a/text()', r.x))[1]::text, (xpath('/row/b/text()', r.x))[1]::text) ORDER BY r.nspname, r.relname), "
    "'[]'::json) FROM (SELECT n.nspname, c.relname, c.relkind, query_to_xml(format(CASE c.relkind WHEN 'S' THEN "
    f"'{_SEQUENCE}' ELSE '{_TABLE}' END, n.nspname, c.relname), false, true, '') AS x "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'S') "
    "AND c.relpersistence <> 't' AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname !~ '^pg_(toast|temp)' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE "
    "d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'){oids}) r")
LIST_SQL = (
    "SELECT coalesce(json_agg(json_build_array(c.oid::bigint, n.nspname, c.relname) ORDER BY 1), '[]'::json) "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'S') "
    "AND c.relpersistence <> 't' AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname !~ '^pg_(toast|temp)' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE "
    "d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')")
# Roles and memberships of the instance (superuser only: pg_authid). The connecting role itself is left out: it is the
# image's bootstrap superuser on both sides, which a restore reconciles but never creates.
ROLES_SQL = (
    "SELECT json_build_array((SELECT coalesce(json_agg(json_build_array(rolname, rolsuper, rolinherit, rolcreaterole, "
    "rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit, rolvaliduntil::text, "
    "CASE WHEN rolpassword IS NULL THEN NULL ELSE md5(rolpassword) END) ORDER BY rolname), '[]'::json) FROM pg_authid "
    "WHERE rolname !~ '^pg_' AND rolname <> current_user), (SELECT coalesce(json_agg(json_build_array(r.rolname, "
    "m.rolname, a.admin_option) ORDER BY r.rolname, m.rolname), '[]'::json) FROM pg_auth_members a JOIN pg_roles r "
    "ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member WHERE m.rolname !~ '^pg_' AND r.rolname <> current_user "
    "AND m.rolname <> current_user))")
DATABASES_SQL = "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY 1"


def in_snapshot(sql):
    """`sql` in one read-only REPEATABLE READ transaction: every table of the digest is read from the same snapshot
    (each query_to_xml() call would otherwise take its own); psql -q prints only the query's result."""
    return f'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n{sql};\nCOMMIT;\n'


def tables_sql(oids=None):
    """TABLES_SQL limited to `oids` (integers from LIST_SQL after the catalog's exclusions), or every relation."""
    if oids is None:
        return TABLES_SQL.replace('{oids}', '')
    listed = ','.join(str(int(oid)) for oid in oids) or '0'
    return TABLES_SQL.replace('{oids}', f' AND c.oid IN ({listed})')


class DigestError(BackupError):
    def __init__(self, message, **details):
        super().__init__('job-failed', message, **details)


def _hex_text(value):
    return bytes.fromhex(value.decode('ascii')).decode('utf-8', 'replace')


def _glob_match(pattern, text):
    import fnmatch
    return fnmatch.fnmatchcase(text, pattern)


def excluded_table(patterns, schema, name):
    """True when `schema.table` matches one of the catalog's exclude_tables globs."""
    text = f'{schema}.{name}'
    return any(_glob_match(pattern, text) for pattern in patterns or ())


# ---------------------------------------------------------------- files

def read_files_detail(path, *, what):
    """Validate a files-digest listing (owner-side output or an archived one); returns (summary, sha256 hex).
    Strict: every line matches the format, paths strictly increase (bytes), at most MAX_ENTRIES lines."""
    counts = dict.fromkeys(SUMMARY_KEYS['files-digest'], 0)
    digest, last = hashlib.sha256(), None
    with open(path, 'rb') as handle:
        while True:
            line = handle.readline(MAX_LINE + 1)
            if not line:
                break
            match = FILE_LINE_RE.fullmatch(line)
            if match is None or len(line) > MAX_LINE:
                raise DigestError(f'{what}的摘要清單格式不正確（第 {counts["entries"] + 1} 行）。')
            path_bytes = bytes.fromhex(match.group(8).decode('ascii'))
            if last is not None and path_bytes <= last:
                raise DigestError(f'{what}的摘要清單沒有依路徑排序或有重複項目。')
            last = path_bytes
            counts['entries'] += 1
            if counts['entries'] > MAX_ENTRIES:
                raise DigestError(f'{what}的項目超過 {MAX_ENTRIES:,} 個。')
            kind = match.group(1).decode()
            if kind == 'f':
                counts['files'] += 1
                counts['bytes'] += int(match.group(5))
            elif kind == 'd':
                counts['dirs'] += 1
            elif kind == 'l':
                counts['symlinks'] += 1
            else:
                counts['other'] += 1
            digest.update(line)
    return counts, digest.hexdigest()


def _file_fields(line):
    match = FILE_LINE_RE.fullmatch(line)
    kind, mode, uid, gid, size, sha, target, rel = (part.decode('ascii') for part in match.groups())
    return rel, {'type': kind, 'mode': mode, 'owner': f'{uid}:{gid}', 'size': size, 'sha256': sha, 'target': target}


def _describe_file_change(before, after):
    labels = {'type': '類型', 'mode': '權限', 'owner': '擁有者', 'size': '大小', 'sha256': '內容', 'target': '連結目標'}
    parts = []
    for key in ('type', 'mode', 'owner', 'size', 'sha256', 'target'):
        if before[key] != after[key]:
            if key == 'type':
                parts.append(f'類型 {FILE_KINDS.get(before[key], before[key])} → {FILE_KINDS.get(after[key], after[key])}')
            elif key in ('mode', 'owner', 'size'):
                parts.append(f'{labels[key]} {before[key]} → {after[key]}')
            else:
                parts.append(f'{labels[key]}不同')
    return '、'.join(parts)


# ---------------------------------------------------------------- postgres

def pg_lines(tables_by_db, roles=None):
    """Canonical lines from psql's JSON answers: {database: [[schema, name, kind, rows, a, b], ...]} and, for a whole
    instance, the ROLES_SQL answer. Validates the shapes (the answers come from inside a container)."""
    def hexed(value, limit=255):
        if not isinstance(value, str) or not value or len(value) > limit:
            raise DigestError('資料庫摘要的名稱格式不正確。')
        return value.encode('utf-8', 'surrogatepass').hex()

    def number(value, signed=False):
        text = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
        if not isinstance(text, str) or not re.fullmatch(r'-?[0-9]{1,40}' if signed else r'[0-9]{1,40}', text):
            raise DigestError('資料庫摘要的數值格式不正確。')
        return text

    lines = set()
    for database, rows in tables_by_db.items():
        if not isinstance(rows, list) or len(rows) > 100000:
            raise DigestError('資料庫摘要的結果格式不正確。')
        lines.add(f'D {hexed(database)}\n')  # the database itself: a missing one differs even when it is empty
        for row in rows:
            if not isinstance(row, list) or len(row) != 6 or row[2] not in ('r', 'S'):
                raise DigestError('資料庫摘要的結果格式不正確。')
            # rows is a count; a and b are sums of signed 64-bit halves of each row's md5 (negative values happen)
            lines.add(f'T {hexed(database)} {hexed(row[0])} {hexed(row[1])} {row[2]} {number(row[3])} '
                      f'{number(row[4], signed=True)} {number(row[5], signed=True)}\n')
    if roles is not None:
        if not isinstance(roles, list) or len(roles) != 2 or not all(isinstance(part, list) for part in roles) \
                or len(roles[0]) > 10000 or len(roles[1]) > 100000:
            raise DigestError('資料庫角色摘要的結果格式不正確。')
        for row in roles[0]:
            if not isinstance(row, list) or len(row) != 11 or not all(isinstance(flag, bool) for flag in row[1:8]):
                raise DigestError('資料庫角色摘要的結果格式不正確。')
            flags = ''.join('t' if flag else 'f' for flag in row[1:8])
            until = '-' if row[9] is None else hexed(row[9], 100)
            password = row[10] if row[10] is None or re.fullmatch(r'[0-9a-f]{32}', str(row[10])) else 'x'
            if password == 'x':
                raise DigestError('資料庫角色摘要的結果格式不正確。')
            lines.add(f'R {hexed(row[0])} {flags} {number(row[8], signed=True)} {until} {password or "-"}\n')
        for row in roles[1]:
            if not isinstance(row, list) or len(row) != 3 or not isinstance(row[2], bool):
                raise DigestError('資料庫角色摘要的結果格式不正確。')
            lines.add(f'M {hexed(row[0])} {hexed(row[1])} {"t" if row[2] else "f"}\n')
    encoded = sorted(line.encode('ascii') for line in lines)
    if len(encoded) > MAX_ENTRIES:
        raise DigestError(f'資料庫摘要的項目超過 {MAX_ENTRIES:,} 個。')
    return encoded


def write_lines(path, lines):
    """Write canonical lines (bytes, sorted) to a new private (0600) file."""
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        for line in lines:
            handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def read_pg_detail(path, *, what):
    """Validate a postgres-digest listing; returns (summary, sha256 hex)."""
    counts = dict.fromkeys(SUMMARY_KEYS['postgres-digest'], 0)
    databases = set()
    digest, last, total = hashlib.sha256(), None, 0
    with open(path, 'rb') as handle:
        while True:
            line = handle.readline(MAX_LINE + 1)
            if not line:
                break
            total += 1
            if PG_LINE_RE.fullmatch(line) is None or total > MAX_ENTRIES:
                raise DigestError(f'{what}的摘要清單格式不正確（第 {total} 行）。')
            if last is not None and line <= last:
                raise DigestError(f'{what}的摘要清單沒有排序或有重複項目。')
            last = line
            fields = line.split()
            if fields[0] == b'D':
                databases.add(fields[1])
            elif fields[0] == b'T':
                databases.add(fields[1])
                if fields[4] == b'S':
                    counts['sequences'] += 1
                else:
                    counts['tables'] += 1
                    counts['rows'] += int(fields[5])
            elif fields[0] == b'R':
                counts['roles'] += 1
            digest.update(line)
    counts['databases'] = len(databases)
    return counts, digest.hexdigest()


def _pg_key(line):
    fields = line.split()
    if fields[0] == b'D':
        return (b'D', fields[1]), []
    if fields[0] == b'T':
        return (b'T', fields[1], fields[2], fields[3], fields[4]), fields[5:]
    if fields[0] == b'R':
        return (b'R', fields[1]), fields[2:]
    return (b'M', fields[1], fields[2]), fields[3:]


def _describe_pg(key):
    if key[0] == b'D':
        return f'資料庫 {_hex_text(key[1])}'
    if key[0] == b'T':
        kind = '序列' if key[4] == b'S' else '資料表'
        return f'{kind} {_hex_text(key[1])}:{_hex_text(key[2])}.{_hex_text(key[3])}'
    if key[0] == b'R':
        return f'角色 {_hex_text(key[1])}'
    return f'角色成員 {_hex_text(key[2])} ∈ {_hex_text(key[1])}'


def _describe_pg_change(key, before, after):
    if key[0] == b'T':
        if before[0] != after[0]:
            return f'資料列 {before[0].decode()} → {after[0].decode()}'
        return '內容不同（筆數相同）'
    if key[0] == b'R':
        parts = []
        if before[0] != after[0]:
            parts.append('屬性不同')
        if before[1] != after[1]:
            parts.append(f'連線上限 {before[1].decode()} → {after[1].decode()}')
        if before[2] != after[2]:
            parts.append('有效期限不同')
        if before[3] != after[3]:
            parts.append('密碼不同')
        return '、'.join(parts) or '不同'
    return '管理權限不同'


# ---------------------------------------------------------------- comparison

def _lines(path):
    with open(path, 'rb') as handle:
        while True:
            line = handle.readline(MAX_LINE + 1)
            if not line:
                return
            yield line


def diff(kind, before_path, after_path, limit=SAMPLES):
    """Merge both sorted listings: {'missing', 'extra', 'changed', 'samples': [{'item', 'change', 'detail'}]}.
    `missing`: in the backup, not after the restore; `extra`: only after the restore. Both files were validated."""
    if kind == 'files-digest':
        def keyed(line):
            rel, fields = _file_fields(line)
            return bytes.fromhex(rel), fields

        def name(key):
            return '（最上層資料夾）' if key == b'.' else key.decode('utf-8', 'replace')

        def change(_key, before, after):
            return _describe_file_change(before, after)
    else:
        keyed, name, change = _pg_key, _describe_pg, _describe_pg_change
    result = {'missing': 0, 'extra': 0, 'changed': 0, 'samples': []}

    def note(kind_, key, detail):
        result[kind_] += 1
        if len(result['samples']) < limit:
            result['samples'].append({'item': name(key)[:300], 'change': kind_, 'detail': detail[:300]})

    left, right = _lines(before_path), _lines(after_path)
    a, b = next(left, None), next(right, None)
    while a is not None or b is not None:
        ka = keyed(a) if a is not None else None
        kb = keyed(b) if b is not None else None
        if kb is None or (ka is not None and ka[0] < kb[0]):
            note('missing', ka[0], '還原後沒有這個項目')
            a = next(left, None)
        elif ka is None or kb[0] < ka[0]:
            note('extra', kb[0], '還原後多出這個項目')
            b = next(right, None)
        else:
            if ka[1] != kb[1]:
                note('changed', ka[0], change(ka[0], ka[1], kb[1]))
            a, b = next(left, None), next(right, None)
    return result


def summary_text(kind, summary):
    """'資料表 12、資料列 345…' for logs."""
    keys = SUMMARY_KEYS.get(kind, ())
    return '、'.join(f'{SUMMARY_LABELS[key]} {summary.get(key, 0):,}' for key in keys if key in summary)


def parse_psql_json(output, what):
    """One JSON value printed by `psql -A -t -c <json query>`."""
    try:
        return json.loads((output or b'').decode('utf-8').strip() or 'null')
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise DigestError(f'{what}的結果不是有效的 JSON。') from None
