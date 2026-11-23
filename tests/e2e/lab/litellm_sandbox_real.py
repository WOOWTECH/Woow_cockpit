#!/usr/bin/env python3
"""LiteLLM HA import security review (2026-11-23), part 3: the REAL owner-made LiteLLM HA backup through the product's
HA-cluster steps WITH the review's fixes, in the isolated lab Podman store (labpodman, --network=none; not dev-d).

  PYTHONPATH=backup-engine:tests/e2e/lab python3 -I tests/e2e/lab/litellm_sandbox_real.py > out.json

What is real: the encrypted showcase backup (fixture SHA-256 checked), opened and decrypted by the product reader
(habackup + hasecuretar; the key read through the existing harness reader ha_import_b1_e2e.Secrets, memory only),
ha_litellm.scan_member + PgSink into a throwaway volume, the pinned official PostgreSQL 18.7, and the product's
start_ha_cluster (pinned session settings), analyse, salt_binding, read_schema, verdict, stored_settings, the table
counts and export_rows (every table's COPY, written to a 0700 scratch folder and deleted at once; only sizes kept).
What it is NOT: the live LiteLLM comparison (there is none here: HA's own migrations stand in for the live ones), the
conversion into PostgreSQL 17, the import, restart and rollback (lane litellm-product's litellm_full_flow.py on dev-d).
Output: fixed facts only (booleans, counts, the product's blocker texts); no value, name of a stored setting or key."""
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for _p in (str(REPO / 'backup-engine'), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from woowbackup import habackup, ha_litellm, ha_odoo, hasecuretar, hastore, tempctr  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
import litellm_sandbox_review as review  # noqa: E402

LAB = Path.home() / '.woowbk-lab'
FIXTURE = LAB / 'ha-fixtures/20261123-litellm/x86/woow-litellm-x86-enc/woow-litellm-x86-enc-20261123.tar'
FIXTURE_SHA256 = '9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27'


def backup_key():
    import ha_import_b1_e2e as b1
    secrets = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                         b1.SECRET_DIR / 'dev-d-markers.json')
    return secrets['HA_BACKUP_KEY']


def main():
    started = time.monotonic()
    facts = {'source': review.source_state()}
    digest = hashlib.sha256()
    with open(FIXTURE, 'rb') as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    facts['fixture_sha256_matches_record'] = digest.hexdigest() == FIXTURE_SHA256
    if not facts['fixture_sha256_matches_record']:
        raise SystemExit('fixture mismatch')
    keys = hasecuretar.Keys(backup_key())
    runner = review.LabRunner()
    work = review.Work()
    job = review.job_id('real')
    scratch = Path(tempfile.mkdtemp(prefix='woowbk-real-', dir=os.environ.get('WOOWBK_REVIEW_SCRATCH')))
    os.chmod(scratch, 0o700)
    try:
        with habackup.open_backup(FIXTURE) as ha, \
                tempctr.TempObjects(runner, job, memory='1g', pids=512, cpus='1') as tmp:
            found = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == ha_litellm.SLUG]
            facts['addon_members'] = len(found)
            member = found[0]
            facts['member_encrypted'] = bool(member.encrypted)
            pg_ids = tmp.user_ids('ids-pg', review.PG18, 'postgres')
            tmp.volume('hapg')
            holder = {}

            def produce(out):
                sink = ha_odoo.PgSink(out, *pg_ids)
                with ha.open_member(member.name, keys) as stream:
                    holder['src'] = ha_litellm.scan_member(stream, habackup.Report(), pg=sink)
                sink.close()

            tmp.volume_import('hapg', produce)
            src = holder['src']
            facts['scan'] = {'pg_version': src.pg_version, 'pg_files': src.pg_files, 'symlinks': src.symlinks,
                             'recovery_files': src.recovery_files, 'salt_valid': src.salt_valid,
                             'state_version': src.state_version}
            cluster = ha_litellm.start_ha_cluster(work, tmp, review.PG18)
            facts['session_settings'] = cluster.query_json(
                "SELECT json_build_object('search_path', current_setting('search_path'), 'datestyle', "
                "current_setting('DateStyle'), 'extra_float_digits', current_setting('extra_float_digits'), "
                "'event_triggers', current_setting('event_triggers'), 'session_preload_libraries', "
                "current_setting('session_preload_libraries'))", ha_litellm.DATABASE)
            analysed = ha_litellm.analyse(cluster)
            binding = ha_litellm.salt_binding(cluster, src)
            ha_schema = ha_litellm.read_schema(cluster, analysed['migrations'])
            blockers, warnings = ha_litellm.verdict(src, analysed, ha_major=ha_litellm._ha_major(src), target_major=17,
                                                    live_migrations_value=analysed['migrations'], binding=binding)
            tables = ha_schema.tables()
            counts = ha_litellm.table_counts(cluster, tables)
            stored = ha_litellm.stored_settings(cluster, ha_schema)
            files, sequences = ha_litellm.export_rows(work, cluster, ha_schema, scratch)
            exported = sum(path.stat().st_size for path in files.values())
            for path in files.values():
                path.unlink()
            facts.update({
                'binding': binding, 'blockers': blockers, 'warnings_count': len(warnings),
                'migrations': len(analysed['migrations'] or []), 'superuser_objects': analysed['superuser'],
                'schemas': analysed['objects'].get('schemas'), 'tables': len(tables),
                'rows_total': sum(v for v in counts.values() if isinstance(v, int)),
                'exported_tables': len(files), 'exported_bytes': exported, 'sequences': len(sequences),
                'stored_settings': None if stored is None else {
                    'sections': len(stored['sections']), 'env_names': len(stored['env']),
                    'callbacks': len(stored['callbacks']),
                    'warning_line': ha_litellm.stored_settings_line(stored) is not None},
                'markers': review.markers(tmp, 'hapg')})
        left = [runner.podman(kind, *args, '--filter', f'name={job}', '--format', '{{.Names}}',
                              max_output=1 << 16).stdout.split() for kind, args in (('ps', ('-a',)), ('volume', ('ls',)))]
        facts['left_behind'] = sum(len(names) for names in left)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    facts['scratch_removed'] = not scratch.exists()
    facts['elapsed_seconds'] = round(time.monotonic() - started, 1)
    facts['commercial_acceptance'] = 'not-complete'
    json.dump(facts, sys.stdout, indent=1, sort_keys=True, ensure_ascii=False)
    sys.stdout.write('\n')


if __name__ == '__main__':
    try:
        main()
    except BackupError as error:
        json.dump({'stopped_with': {'code': error.code, 'message': str(error)[:300]}}, sys.stdout, ensure_ascii=False)
        sys.stdout.write('\n')
        raise SystemExit(1)
