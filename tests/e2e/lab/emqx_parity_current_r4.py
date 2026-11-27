#!/usr/bin/env python3
"""Run the existing isolated EMQX R4 driver with the owner's later D0 access policy.

The old driver retains tests for the superseded file-ACL refusal. This entry point
updates only the expectations for real arm/x86 cold fixtures and the imported broker.
It uses the old driver's dev-d lock, baseline backup, cleanup and secret masking.
"""
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('emqx_product_real_ha', HERE / 'emqx_product_real_ha.py')
real = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real)
old_evaluate = real.evaluate_imported


def source_access(machine):
    path = Path(real.drv.SOURCE).parent / machine / 'emqx-api.json'
    doc = json.loads(path.read_text(encoding='utf-8'))
    return (doc['authorization_settings'],
            [[item['type'], item['enable']] for item in doc['authorization_sources']],
            sorted([item['id'], item['enable']] for item in doc['authentication']))


def check_one(ev, args, tag, *, mode):
    """D0: both real backups remain importable on a file-only or mixed target."""
    key = real.ha_key(args, tag)
    job, took = real.drv.run_check(real.drv.STATE[f'ha_{tag}'], ['emqx'], ev=ev, key=key,
                                  tag=f'check-{tag}-{mode}-emqx')
    ev.time('check', tag, 'emqx', took, job)
    label = f'check {tag}/emqx ({mode} target, D0)'
    if not ev.check(f'{label}: job succeeded', job['state'] == 'succeeded',
                    f'{took:.0f} s {job.get("error")}'):
        return None
    result = job['result']['ha_check']['apps'][0]
    ev.save(f'check-{tag}-{mode}-emqx.json', result)
    section = result.get('emqx') or {}
    ev.check(f'{label}: importable, no blocker', result.get('ok') is True and not result.get('blockers'),
             result.get('blockers'))
    ev.check(f'{label}: HA access replaces the target',
             any(i.get('id') == 'emqx.access-from-ha' and i.get('level') == 'auto'
                 for i in result.get('issues') or []),
             [(i.get('id'), i.get('level')) for i in result.get('issues') or []])
    ev.check(f'{label}: no target authorization restriction',
             section.get('target_authorization') == [], section.get('target_authorization'))
    machine = real.machine_of(tag)
    ev.check(f'{label}: source and target versions',
             result.get('arch') == ('aarch64' if machine == 'arm' else 'amd64')
             and result.get('version') == '5.9.1' and result.get('target_version') == '5.8.9',
             {key: result.get(key) for key in ('arch', 'version', 'target_version')})
    real.drv.compare_check(ev, label, 'emqx', result, machine, False, tag)
    return result


def evaluate_imported(probe, src, mode, *, acl_rows=4):
    """Use the old positive checks, and compare access policy with the HA source facts."""
    rows = old_evaluate(probe, src, 'builtin', acl_rows=acl_rows)
    superseded = ('authorization settings are this device',
                  'authorization sources are this device',
                  'the file ACL reads back byte-equal',
                  "MQTT: this device's file rule")
    rows = [row for row in rows if not row[0].startswith(superseded)]
    # Both recorded real fixtures have the same access policy (checked below).
    settings, sources, authn = source_access('x86')
    rows.append(('authorization settings equal HA', probe.get('authz_settings') == settings,
                 probe.get('authz_settings')))
    rows.append(('authorization sources equal HA, in order', probe.get('authz_sources') == sources,
                 probe.get('authz_sources')))
    rows.append(('authentication sources equal HA', probe.get('authenticators') == authn,
                 probe.get('authenticators')))
    return rows


real.check_one = check_one
real.evaluate_imported = evaluate_imported
# R4 first checks the normal import and its post-import rollback. The separate
# one-shot failures before a first import were exercised by the earlier product run.
real.FIRST_ROUNDS = ()

if __name__ == '__main__':
    if sys.argv[1:] == ['--self-check']:
        real.self_check()
        for machine in ('x86', 'arm'):
            settings, sources, _ = source_access(machine)
            assert settings['no_match'] == 'allow'
            assert sources == [['built_in_database', True], ['file', True]]
        assert source_access('x86') == source_access('arm')
        print('D0 source policy self-check passed')
        raise SystemExit(0)
    raise SystemExit(real.main(sys.argv[1:]))
