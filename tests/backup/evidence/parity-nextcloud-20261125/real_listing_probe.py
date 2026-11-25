#!/usr/bin/env python3
"""A REAL `pg_restore -l` listing (PostgreSQL 16.15, the live Nextcloud database of the dev-e lab device, read 2026-11-23 by this
lane's shape probe) through the listing code of ha_nextcloud: the numbers only, no object name, no content.
  python3 -I real_listing_probe.py <repo with backup-engine> <listing file>
The first version of check_listing asked `TOC Entries` to be the entry lines + 3 exactly and refused this listing (1136 vs 1131 + 3);
the ODOO lane found it (parity/odoo-20261125@6f35b77), the integrator applied the same change as fb2c43f."""
import json
import re
import sys

sys.path.insert(0, sys.argv[1] + '/backup-engine')
from woowbackup import ha_nextcloud as nc, ha_odoo   # noqa: E402

text = open(sys.argv[2], encoding='utf-8', errors='surrogateescape').read()
entries, declared, shown = nc.toc_entries(text)
kinds = sorted(set(nc.toc_kinds(text)))
skipped = nc.skip_toc(text, nc.SKIPPED_TOC)
print(json.dumps({'header_toc_entries': declared, 'entry_lines': entries, 'archive_settings_shown': shown,
                  'held_back': declared - entries, 'check_listing': nc.check_listing(text), 'kinds': kinds,
                  'kinds_outside_the_allowed': [k for k in kinds if k not in nc.TOC_ALLOWED],
                  'superuser_only_kinds': ha_odoo.superuser_kinds(text),
                  'lines': len(text.splitlines()), 'lines_when_programs_are_left_out': len(skipped.splitlines()),
                  'lines_not_entries_or_comments': sum(1 for l in text.splitlines() if l.strip() and not l.startswith(';')
                                                       and not re.match(r'\s*\d+;\s+\d+\s+\d+\s', l))}, sort_keys=True, indent=1))
