"""Opt-in dev-d PG17 synthetic SQL contract test; never uses host production.

Run only after coordination with other dev-d users. The image must already be in dev-d.
No network, production mounts, credentials or services are used.
"""
import argparse
import datetime
import hashlib
import json
import secrets

from woowbackup import ha_litellm_candidate as candidate, ha_odoo, tempctr
from litellm_version_candidate import DevDRunner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db-image-id', required=True)
    args = parser.parse_args()
    if not candidate._IMAGE_ID.fullmatch(args.db_image_id):
        raise SystemExit('A full already-loaded image ID is required')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    job = 'j' + stamp + '-' + secrets.token_hex(4)
    salt = b'sk-' + b'a' * 64  # intentionally synthetic
    fingerprint = hashlib.sha256(b'woow-litellm-salt-v1:' + salt).hexdigest()[:16]
    results = {}
    cleanup_notes = []
    with tempctr.TempObjects(DevDRunner(), job, memory='128m', pids=128, cpus=None,
                             log=cleanup_notes.append) as tmp:
        tmp.volume('litellm-sql-data')
        tmp.run('litellm-sql-pg', args.db_image_id,
                ['postgres', '-c', 'shared_buffers=16MB', '-c', 'max_connections=20'],
                detach=True, read_only_root=True,
                volumes=[(tmp.name('litellm-sql-data'), '/var/lib/postgresql/data', 'rw,noexec,nosuid,nodev')],
                env={'POSTGRES_HOST_AUTH_METHOD': 'trust', 'POSTGRES_DB': 'litellm'})
        cluster = ha_odoo.Cluster(tmp, 'litellm-sql-pg')
        cluster.wait_ready(tcp=True, timeout=120)
        cluster.script("CREATE ROLE woowbk_litellm_reader LOGIN;\n"
                       "CREATE SCHEMA woow; CREATE SCHEMA woow_platform;\n"
                       "CREATE TABLE woow.meta (key text, value text);\n"
                       "CREATE TABLE woow_platform.settings (key text, value text);\n"
                       "GRANT USAGE ON SCHEMA woow, woow_platform TO woowbk_litellm_reader;\n"
                       "GRANT SELECT ON woow.meta, woow_platform.settings TO woowbk_litellm_reader;\n"
                       "INSERT INTO woow.meta VALUES ('salt_fingerprint_v1', '" + fingerprint + "');\n"
                       "INSERT INTO woow_platform.settings VALUES ('litellm_salt_key', '" + salt.decode() + "');\n",
                       'litellm')
        def probe(name, expected):
            observed = candidate.read_source_salt_binding(cluster, salt)
            results[name] = observed == expected
        probe('matching_rows', 'match')
        cluster.script("UPDATE woow_platform.settings SET value = repeat('b', 64);", 'litellm')
        probe('salt_mismatch', 'mismatch')
        cluster.script("UPDATE woow_platform.settings SET value = '" + salt.decode() + "';\n"
                       "UPDATE woow.meta SET value = repeat('0', 16);", 'litellm')
        probe('fingerprint_mismatch', 'mismatch')
        cluster.script("DELETE FROM woow.meta;", 'litellm')
        probe('missing_fingerprint', 'invalid_rows')
        cluster.script("INSERT INTO woow.meta VALUES ('salt_fingerprint_v1', '" + fingerprint + "');\n"
                       "INSERT INTO woow_platform.settings SELECT * FROM woow_platform.settings;", 'litellm')
        probe('duplicate_salt_rows', 'invalid_rows')
        cluster.script("DELETE FROM woow_platform.settings;\n"
                       "INSERT INTO woow_platform.settings VALUES ('litellm_salt_key', repeat('x', 257));", 'litellm')
        probe('oversized_salt', 'invalid_rows')
        cluster.script("DROP TABLE woow.meta; CREATE VIEW woow.meta AS SELECT 'salt_fingerprint_v1'::text AS key, "
                       "'" + fingerprint + "'::text AS value;\n"
                       "GRANT SELECT ON woow.meta TO woowbk_litellm_reader;", 'litellm')
        probe('view_refused', 'unknown')
    output = {'scope': 'synthetic PG17 SQL query contract only', 'cases': results,
              'cleanup_notes': len(cleanup_notes), 'conversion': 'disabled'}
    print(json.dumps(output, sort_keys=True))
    return 0 if results and all(results.values()) and not cleanup_notes else 1


if __name__ == '__main__':
    raise SystemExit(main())
