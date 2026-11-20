#!/usr/bin/env python3
"""dev-d only; synthetic appowner EMQX restore/rollback integration driver.

Run only via labpodman inside the isolated dev-d device. The caller supplies a
full already-present image ID and an isolated private staging directory.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import time

from emqx_adapter_provision import Provision
from emqx_adapter_flow import package_candidate_and_restore
from woowbackup import catalog, flows
from woowbackup.paths import Paths

CLIENT = 'sha256:93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3'


class Reporter:
    cancellable = False
    def phase(self, *a, **k): pass
    def skip(self, *a, **k): pass
    def complete(self, *a, **k): pass
    def fail(self, *a, **k): pass
    def mark(self, *a, **k): pass
    def add_phase(self, *a, **k): pass
    def log(self, *a, **k): pass
    def set_partial(self, **k): pass
    def set_cancellable(self, flag): self.cancellable = flag; return False
    def cancel_requested(self): return False
    def progress(self, *a, **k): pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    if (args.work.parent != Path('/tmp') or not re.fullmatch(r'woowbk-emqxlab-[0-9a-f]{8}', args.work.name)
            or args.work.exists() or args.work.is_symlink()):
        raise RuntimeError('work directory must be a new synthetic /tmp path')
    provision = Provision(args.image_id)
    f, runner = provision.fixture, provision.runner
    password = secrets.token_hex(16)
    base = b'''authentication = [{mechanism = password_based, backend = built_in_database,
password_hash_algorithm {name = sha256, salt_position = suffix},
bootstrap_file = "/opt/emqx/etc/lab-bootstrap.csv", bootstrap_type = plain}]
authorization {no_match = deny, deny_action = ignore,
sources = [{type = file, enable = true, path = "/opt/emqx/etc/lab-acl.conf"}]}
listeners.tcp.default.bind = "127.0.0.1:1883"
retainer.backend.storage_type = disc
'''
    acl = b'{allow, {username, "lab"}, all, ["lab/#"]}.\n{deny, all}.\n'
    dropin = '.config/systemd/user/' + f.unit + '.d/woowbk-inject.conf'
    marker = '.config/' + f.prefix + '/fail-once'
    dropin_created = False
    dropin_dir_created = False
    work_created = False
    try:
        provision.create(base, acl, ('user_id,password,is_superuser\nlab,' + password + ',false\n').encode())
        runner.systemctl('start', '--', f.unit, timeout=180)
        def ready():
            deadline = time.monotonic() + 120
            while True:
                result = runner.podman('exec', f.prefix, 'emqx', 'ctl', 'status', check=False, timeout=30)
                if result.returncode == 0 and b'is started' in result.stdout:
                    return
                if time.monotonic() > deadline:
                    raise RuntimeError('synthetic broker not ready')
                time.sleep(2)
        ready()
        inspection = json.loads(runner.podman('container', 'inspect', f.prefix).stdout)[0]
        f.validate_inspection(inspection)

        def configuration():
            expr = ('io:format("WOOWCFG:~s:END~n", '
                    '[base64:encode(emqx_utils_json:encode(emqx:get_raw_config([])))]).')
            raw = runner.podman('exec', f.prefix, 'emqx', 'eval', expr).stdout.strip()
            if not raw.startswith(b'WOOWCFG:') or b':END' not in raw:
                raise RuntimeError('cannot read synthetic effective config')
            return json.loads(base64.b64decode(raw[8:].split(b':END', 1)[0], validate=True))

        def mqtt(program, topic, payload=None):
            argv = ['run', '--rm', '--pull=never', '--network=container:' + f.prefix,
                    '--memory=64m', '--cpus=1', '--entrypoint=' + program, CLIENT,
                    '-h', '127.0.0.1', '-p', '1883', '-V', 'mqttv5', '-q', '1',
                    '-u', 'lab', '-P', password, '-t', topic]
            argv += ['-r', '-m', payload, '-d'] if payload is not None else ['-C', '1', '-W', '10']
            return runner.podman(*argv, timeout=60, check=False)

        def publish(topic, payload):
            result = mqtt('mosquitto_pub', topic, payload)
            if result.returncode != 0 or not re.search(rb'RC:(?:0|16)\b', result.stdout):
                raise RuntimeError('synthetic publication was not acknowledged')

        def receive(topic, payload):
            result = mqtt('mosquitto_sub', topic)
            if result.returncode or result.stdout.strip() != payload.encode():
                raise RuntimeError('synthetic retained marker mismatch')

        publish('lab/candidate', 'candidate-marker')
        receive('lab/candidate', 'candidate-marker')
        args.work.mkdir(mode=0o700)
        work_created = True
        paths = Paths(base=args.work / 'engine')
        app = catalog.validate_entry(f.catalog(), paths=paths)
        deps = flows.default_deps(paths)
        deps.load_catalog = lambda: catalog.Catalog({app.id: app})
        deps.encrypt_by_default = lambda: False
        deps.sweep_temp = None
        deps.audit = lambda _line: None
        state = {'arm': False, 'injected': False}
        original_factory = deps.adapter_factory
        def adapter_factory(app_, **kwargs):
            original_hook = kwargs.get('imported_hook')
            def imported():
                if original_hook:
                    original_hook()
                if state['arm'] and not state['injected']:
                    runner.write_file(marker, b'fail once\n', 0o600)
                    state['injected'] = True
            kwargs['imported_hook'] = imported
            return original_factory(app_, **kwargs)
        deps.adapter_factory = adapter_factory
        job = 'j' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(4)
        ctx = flows.FlowContext(paths, job, deps, Reporter())
        candidate_adapter = ctx.adapter(app)
        manifest, entries = candidate_adapter.backup(args.work / 'candidate', include_images=False)
        ready()
        entry_sources = {e.path: e.source for e in entries}
        volumes = {row['name']: entry_sources[row['entry']] for row in manifest['volumes']}
        publish('lab/before-rollback', 'rollback-marker')
        receive('lab/before-rollback', 'rollback-marker')
        before_config = configuration()
        command = ('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + marker +
                   '; then rm -f %h/' + marker + '; exit 1; fi\'\n')
        runner.run(['/usr/bin/mkdir', '--', runner.home + '/.config/systemd/user/' + f.unit + '.d'])
        dropin_dir_created = True
        runner.write_file(dropin, command.encode(), 0o600)
        dropin_created = True
        runner.systemctl('daemon-reload')
        def arm():
            state['arm'] = True
        try:
            package_candidate_and_restore(ctx, app, volumes, args.work / 'package', before_restore=arm)
            raise RuntimeError('restore unexpectedly succeeded')
        except flows.RolledBack as outcome:
            if not outcome.result.get('rolled_back') or not state['injected']:
                raise RuntimeError('expected automatic rollback was not established')
        ready()
        if runner.stat_files([marker])[marker]['type'] != 'missing':
            raise RuntimeError('one-shot failure marker was not consumed')
        if configuration() != before_config:
            raise RuntimeError('synthetic configuration did not roll back')
        receive('lab/before-rollback', 'rollback-marker')
        receive('lab/candidate', 'candidate-marker')
        denied = mqtt('mosquitto_pub', 'outside/denied', 'should-not-publish')
        if not re.search(rb'RC:135\b', denied.stdout + denied.stderr):
            raise RuntimeError('synthetic ACL denial was not observed')
        f.validate_inspection(json.loads(runner.podman('container', 'inspect', f.prefix).stdout)[0])
        runner.systemctl('restart', '--', f.unit, timeout=180)
        ready()
        if configuration() != before_config:
            raise RuntimeError('synthetic configuration changed on restart')
        receive('lab/before-rollback', 'rollback-marker')
    finally:
        errors = []
        if dropin_created:
            try:
                runner.remove_file(dropin)
                runner.remove_file(marker)
                runner.systemctl('daemon-reload')
            except Exception:
                errors.append('dropin')
        if dropin_dir_created:
            try:
                runner.run(['/usr/bin/rmdir', '--', runner.home + '/.config/systemd/user/' + f.unit + '.d'])
            except Exception:
                errors.append('dropin-directory')
        try:
            provision.cleanup()
        except Exception as error:
            errors.append('resources:' + str(error))
        if work_created:
            try:
                shutil.rmtree(args.work)
            except Exception:
                errors.append('staging')
        if errors:
            raise RuntimeError('cleanup incomplete: ' + ','.join(errors))
    print(json.dumps({'stage': 'adapter_automatic_rollback', 'result': 'pass', 'cleanup': 'pass'}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'stage': 'adapter_test', 'result': 'fail', 'error_type': type(error).__name__}), flush=True)
        raise SystemExit(1) from None
