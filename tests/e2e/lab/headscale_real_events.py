#!/usr/bin/env python3
"""Credential-event profile for the real-HA Headscale run (services-a).

Reuses the acknowledged event controller of headscale-credential-events.py
unchanged (register-before-acknowledge, ordered sources, withheld output, log
and output scans, fixed failure text) with this run's exact source list. The
profile comes from HS_REAL_ARCH (arm|x86) and HS_REAL_INSTALLER (0|1), which
the controller passes to every producer, so both sides validate one list.
"""
import importlib.util
import os
from pathlib import Path
import sys

_spec = importlib.util.spec_from_file_location('headscale_credential_events',
                                               Path(__file__).with_name('headscale-credential-events.py'))
events = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(events)


def profile(arch, installer):
    """(EXPECTED ordered sources, AUTH_SOURCES, LOGS) for one real run."""
    if arch not in ('arm', 'x86') or installer not in ('0', '1'):
        raise ValueError('invalid real profile')
    expected = ['ca_private', 'tls_private', 'target_api', 'target_noise', 'target_derp',
                'ha_noise', 'configtest_keys']
    if arch == 'arm':
        expected.append('client_identity_before')
    expected += ['ha_preauth', 'probe_a_identity']
    if arch == 'x86':
        expected.append('probe_b_identity')
    expected.append('restored_keys')
    if installer == '1':
        expected.append('installed_keys')
    if arch == 'arm':
        expected.append('client_identity_after')
    logs = ['target_initial', 'configtest', 'probe_a', 'restored_server']
    if arch == 'x86':
        logs.append('probe_b')
    if installer == '1':
        logs.append('installed_server')
    if arch == 'arm':
        logs.append('client_alice')
    return tuple(expected), frozenset(('target_api', 'ha_preauth')), tuple(logs)


def configure(environ=os.environ):
    expected, auth, logs = profile(environ.get('HS_REAL_ARCH', ''), environ.get('HS_REAL_INSTALLER', ''))
    events.EXPECTED, events.AUTH_SOURCES, events.LOGS = expected, auth, logs
    return expected, auth, logs


if __name__ == '__main__':
    try:
        configure()
    except ValueError:
        print('Real credential profile invalid; nothing run', file=sys.stderr)
        raise SystemExit(2) from None
    events.main()
