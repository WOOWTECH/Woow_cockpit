"""ncs_leakscan.py <files...>: counts occurrences of every lab test credential value (>= 8 characters, any name in
~/.woowbk-lab/secrets/{ha-import-creds,b1-creds}.env) and of the Supervisor/SSH helper secret names' values in the
given files. Prints one line per file with the hit count only (never a value or a name of a hit)."""
import sys
from pathlib import Path

vals = set()
for name in ('ha-import-creds.env', 'b1-creds.env'):
    for line in (Path.home() / '.woowbk-lab/secrets' / name).read_text(encoding='utf-8').splitlines():
        k, sep, v = line.strip().partition('=')
        if sep and not k.startswith('#') and len(v.strip()) >= 8:
            vals.add(v.strip().encode())
total = 0
for f in sys.argv[1:]:
    data = Path(f).read_bytes()
    hits = sum(data.count(v) for v in vals)
    total += hits
    print(f'{Path(f).name}: {hits} hits')
print(f'TOTAL {total} hits over {len(sys.argv) - 1} files ({len(vals)} values checked)')
sys.exit(1 if total else 0)
