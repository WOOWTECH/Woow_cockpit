#!/usr/bin/env python3
"""H-03: real encrypted HA Hermes import with this device's unused PostgreSQL in whole-instance mode.

Runs on network-isolated dev-d under its mutation lock. Reuses the actual installed-helper Hermes flow, adds one
disposable database/NOLOGIN role, verifies its data/owner and every role's password fingerprint after import, restart
and safety rollback, then restores the original catalog and removes only the probe it created. No product mocks.
Private evidence uses the existing Hermes evidence/secret handling; stdout contains fixed statuses only.

  python3 -I tests/e2e/lab/hermes_instance_real.py --run
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hermes_instance_base', HERE / 'hermes_real_ha.py')
hr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hr)
drv = hr.drv


def instance_entry(original):
    entry = copy.deepcopy(original)
    if len(entry.get('postgres') or []) != 1:
        raise hr.Failed('this case requires exactly one existing PostgreSQL item')
    pg = entry['postgres'][0]
    if pg.get('scope', 'database') not in ('database', 'instance'):
        raise hr.Failed('unexpected original PostgreSQL scope')
    pg['scope'] = 'instance'
    pg.pop('database', None)
    return entry


def identifier(name):
    if not re.fullmatch(r'woowbk_instance_[a-f0-9]{12}(?:_role)?', name):
        raise hr.Failed('invalid disposable probe name')
    return '"' + name + '"'


def sql(pg, database, text):
    result = drv.owner('podman', 'exec', '-i', pg['container'], 'psql', '-X', '-w', '-A', '-t', '-q',
                       '-v', 'ON_ERROR_STOP=1', '-U', pg['user'], '-d', database, '-f', '-',
                       input=text.encode(), timeout=180)
    if result.returncode:
        raise hr.Failed('instance probe SQL failed; private command result withheld')
    return drv.out(result).strip()


def catalog_set(entry, ev):
    preview = drv.ok('catalog-install', {'entry': entry}, ev=ev, timeout=300)
    if preview.get('valid') is not True:
        raise hr.Failed('instance probe catalog preview refused')
    drv.ok('catalog-install', {'entry': entry, 'confirm': True,
                             'expected_sha256': preview.get('expected_sha256')}, ev=ev, timeout=300)


def roles(pg):
    # Compare password state without moving a password hash into a public record or log.
    return sql(pg, 'postgres', "SELECT md5(coalesce(string_agg(rolname || ':' || coalesce(rolpassword, ''), "
               "E'\\n' ORDER BY rolname), '')) FROM pg_authid;")


def probe(pg, database):
    return json.loads(sql(pg, database, "SELECT json_build_array("
                          "(SELECT array_agg(value ORDER BY value) FROM public.kept_marker), "
                          "(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()), "
                          "(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.kept_marker'::regclass));"))


def run():
    if not hr.clean_tree():
        raise hr.Failed('commit tested code first')
    hr.emit('source commit ' + hr.git('rev-parse', 'HEAD'))
    secret_values = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env', drv.SECRET_DIR / 'ha-import-creds.env'],
                               drv.SECRET_DIR / 'dev-d-markers.json')
    args = SimpleNamespace(secrets=secret_values, kit=None)
    ev = hr.Evidence(secret_values)
    drv.load_state()
    drv.STATE['run_started'] = int(time.time()) - 60
    hr.verify_isolation()
    fd = hr.acquire_lock()
    started = time.monotonic()
    original = pg = None
    database = 'woowbk_instance_' + secrets.token_hex(6)
    role = database + '_role'
    changed = seeded_role = seeded_database = False
    old_roles = None
    timer = drv.out(drv.root('systemctl', 'is-enabled', hr.TIMER, timeout=60)).strip()
    success = False
    try:
        for name, step in (('setup', hr.step_setup), ('before', hr.step_before), ('check', hr.step_check)):
            hr.headroom()
            step(ev, args)
            if any(not result['ok'] for result in ev.results):
                raise hr.Failed('a required ' + name + ' check failed')
        original = drv.catalog('hermes')
        target = instance_entry(original)
        pg = target['postgres'][0]
        old_roles = roles(pg)
        sql(pg, 'postgres', 'CREATE ROLE ' + identifier(role) + ' NOLOGIN;')
        seeded_role = True
        sql(pg, 'postgres', 'CREATE DATABASE ' + identifier(database) + ' OWNER ' + identifier(role) + ';')
        seeded_database = True
        sql(pg, database, "CREATE TABLE public.kept_marker(value text); "
            "INSERT INTO public.kept_marker VALUES ('same across the HA import'); "
            'ALTER TABLE public.kept_marker OWNER TO ' + identifier(role) + ';')
        expected = probe(pg, database)
        expected_roles = roles(pg)
        catalog_set(target, ev)
        changed = True
        ev.check('instance: catalog changed only to complete-instance mode',
                 drv.catalog('hermes') == target)

        def verify(phase):
            equal = probe(pg, database) == expected and roles(pg) == expected_roles
            ev.check('instance: data owners and all role passwords preserved after ' + phase, equal)
            if not equal:
                raise hr.Failed('instance data changed at ' + phase)

        hr.step_import(ev, args, 'x86-enc', on_verified=verify)
        success = not any(not result['ok'] for result in ev.results)
    finally:
        try:
            # A still-running helper owns its resources: retain probe/catalog rather than racing its restore.
            if any(drv.labelled().values()):
                raise hr.Failed('job resources still exist; retain catalog and probe for recovery')
            if changed:
                catalog_set(original, ev)
                ev.check('cleanup: original Hermes catalog restored', drv.catalog('hermes') == original)
            if seeded_database:
                sql(pg, 'postgres', 'DROP DATABASE ' + identifier(database) + ';')
            if seeded_role:
                sql(pg, 'postgres', 'DROP ROLE ' + identifier(role) + ';')
            if old_roles is not None:
                ev.check('cleanup: original role-password fingerprint restored', roles(pg) == old_roles)
            hr.step_cleanup(ev, args)
            hr.step_leaks(ev, args)
        except Exception as error:
            success = False
            ev.check('cleanup: completed without an error', False, type(error).__name__)
            raise
        finally:
            if timer not in ('masked', 'masked-runtime'):
                drv.root('systemctl', 'unmask', hr.TIMER, timeout=120, check=True)
            hr.verify_isolation()
            os.close(fd)
            hr.emit('lock held for ' + str(int(time.monotonic() - started)) + ' s')
            drv.save_state()
            ok = ev.finish()
            passed = sum(result['ok'] for result in ev.results)
            hr.emit(f'hermes instance full flow: {passed}/{len(ev.results)} ' + ('PASS' if success and ok else 'FAIL'))
    return 0 if success and ok else 1


if __name__ == '__main__':
    if sys.argv[1:] != ['--run']:
        raise SystemExit('Usage: hermes_instance_real.py --run (isolated dev-d only)')
    raise SystemExit(run())
