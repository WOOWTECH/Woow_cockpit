"""Bounded plaintext bootstrap CSV value collection, no IO or policy approval.

Only the fixed vendor observer opts into an actually observed header-only file.
Invocation-owned fixture CSVs retain the seeded-row requirement by default.
"""
import csv
import io

LIMIT = 65536
HEADER = ['user_id', 'password', 'is_superuser']


def collect_bootstrap_csv(raw, values, *, allow_header_only=False):
    if (type(raw) is not bytes or not 0 < len(raw) <= LIMIT or
            type(allow_header_only) is not bool):
        raise ValueError()
    text = raw.decode('utf-8')
    if '\x00' in text or text.startswith('\ufeff'):
        raise ValueError()
    rows = list(csv.reader(io.StringIO(text, newline=''), strict=True))
    minimum = 1 if allow_header_only else 2
    if not minimum <= len(rows) <= 257 or rows[0] != HEADER:
        raise ValueError()
    users = set()
    for row in rows[1:]:
        if (len(row) != 3 or not row[0] or not row[1] or row[2] not in ('true', 'false') or
                row[0] in users or any('\n' in x or '\r' in x for x in row)):
            raise ValueError()
        users.add(row[0])
    values.add(raw)
    for row in rows:
        for field in row:
            values.add(field.encode('utf-8'))
    return len(rows) - 1
