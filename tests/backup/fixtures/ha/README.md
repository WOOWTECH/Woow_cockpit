# Home Assistant backup fixtures

Small Home Assistant (Supervisor) backups for `tests/backup/test_ha_*.py`, written by the **real** securetar
library, the way Supervisor calls it. The tests only read these files; they never need securetar.

| File | Writer | Encryption | Members |
| --- | --- | --- | --- |
| `v1_gzip.tar` | securetar 2024.11.0 (Supervisor 2024.12.3) | v1 (no header, AES-128-CBC; gzip trailer padded per write) | Odoo, n8n, share, supervisor |
| `v1_plain.tar` | securetar 2024.11.0 | v1, `compressed: false` (securetar 2026.10.0 truncates these) | Odoo, supervisor |
| `v2_2025_gzip.tar` | securetar 2025.12.0 (Supervisor 2025.12.3) | v2 | Odoo, n8n, share, supervisor |
| `v2_gzip.tar` | securetar 2026.10.0, `create_version=2` (Supervisor 2026.02.3–2026.03.0) | v2 | Odoo, n8n, share, supervisor |
| `v3_gzip.tar` | securetar 2026.10.0, `create_version=3` (Supervisor 2026.11.0 with Core 2026.7) | v3 (XChaCha20-Poly1305 secretstream) | Odoo, n8n, share, supervisor |
| `v3_plain.tar` | securetar 2026.10.0, `create_version=3` | v3, `compressed: false` | Odoo, supervisor |
| `plain_gzip.tar` | securetar 2026.10.0 without a password | none | Odoo, n8n, share, supervisor |
| `downloaded_gzip.tar` | the members of `v3_gzip.tar` decrypted with securetar 2026.10.0 | none, except `supervisor.tar.gz` (still v3) | like Home Assistant's download button: `protected: false` |

Each file is a plain PAX outer tar with `./backup.json` written last. The inner trees copy the layout of real
WOOWTECH add-on backups (`addon.json`, `data/postgres` owned 100:102, `data/odoo/filestore` and `data/addons` owned
101:103, `config/.n8n` with a relative and an escaping symlink, `data/options.json`, `data/odoo.conf` and
`data/n8n-runners-auth-token` with made-up secrets listed in `fixtures.json` `secrets`). The password
`ABCD-EFGH-JKLM-NPQR-STUV-WXY2-3456` is made up for these fixtures only.

`fixtures.json` records, per member: its encryption, the sha256 and length of the plaintext that securetar 2026.10.0
returns for it (byte-identical decryption is tested against these; v1 uncompressed members have
`library_truncates: true` instead), and every entry that was written (name, type, mode, uid, gid, size, sha256,
link target), so the tests check the whole read path.

## Regenerating

Never with the system Python and never inside this repository's environment. In a scratch directory (downloaded
packages are untrusted: `python -I`, the venv outside the repo):

```bash
python3 -m venv /path/to/venv
/path/to/venv/bin/pip install securetar==2026.10.0          # brings cryptography and PyNaCl
/path/to/venv/bin/pip install --no-deps --target /path/to/st-2024.11.0 securetar==2024.11.0
/path/to/venv/bin/pip install --no-deps --target /path/to/st-2025.12.0 securetar==2025.12.0
OUT=$(mktemp -d)
PY=/path/to/venv/bin/python; G=tests/backup/fixtures/ha/generate.py
$PY -I $G build-v1      --out $OUT --lib /path/to/st-2024.11.0
$PY -I $G build-v2-2025 --out $OUT --lib /path/to/st-2025.12.0
$PY -I $G build         --out $OUT
$PY -I $G record        --out $OUT
cp $OUT/*.tar $OUT/fixtures.json tests/backup/fixtures/ha/
```

The committed files were made on 2026-11-18 with securetar 2026.10.0 (cryptography 50.0.2, PyNaCl 1.6.2), 2025.12.0
and 2024.11.0. Salts and nonces are random, so a new run gives different bytes with the same structure; the tests
only rely on `fixtures.json`.

The real Home Assistant backups made for this feature (Supervisor 2026.11.0) are **never** committed; set
`WOOWBK_HA_FIXTURES` (their directory) and `WOOWBK_HA_KEY` to run `test_ha_backup.RealBackupTests` against them.
