#!/usr/bin/python3
"""Fixture-only resource wrapper: every allowed operation executes the real Podman binary, never fabricates an answer."""
import os
from pathlib import Path
import secrets
import sys

CLIENT = 'docker.io/library/eclipse-mosquitto:2.0.22@sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c'


def guarded_args(args, scratch):
    args = list(args)
    if args[:1] == ['run']:
        if args.count(CLIENT) != 1 or args[:5] != ['run', '--rm', '--pull=missing', '--network', 'woow_emqx_network']:
            raise ValueError('only_package_mqtt_client_runs')
        image = args.index(CLIENT)
        if args[image + 1] not in ('mosquitto_pub', 'mosquitto_sub'):
            raise ValueError('only_package_client_programs')
        command = args[image + 1:]
        if command[command.index('-h') + 1] != 'woow-emqx' or command[command.index('-p') + 1] != '1883':
            raise ValueError('only_owned_broker_endpoint')
        options = args[5:image]
        if options:
            if len(options) != 4 or options[:3] != ['-e', 'XDG_CONFIG_HOME=/cfg', '-v']:
                raise ValueError('unexpected_client_options')
            source, sep, target = options[3].partition(':')
            if not sep or target != '/cfg:ro' or not Path(source).resolve().is_relative_to(Path(scratch).resolve()):
                raise ValueError('only_owned_client_configuration')
        args[2] = '--pull=never'
        args[1:1] = ['--image-volume=ignore', '--memory=128m', '--memory-swap=128m', '--cpus=0.25',
                     '--pids-limit=64', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                     '--name=woow-r4-client-' + str(os.getpid()) + '-' + secrets.token_hex(4)]
        return args
    # The unchanged health waiter actively runs these real healthchecks as well as inspecting them.
    if len(args)==3 and args[:2]==['healthcheck','run'] and args[2] in ('woow-emqx','woow-emqx-entrance'):
        return args
    # Only reads made by unchanged smoke/quadlet-lib, in a dedicated empty-then-fixture-only store.
    if args and args[-1] in ('woow-emqx','woow-emqx-entrance'):
        if args[:-1] in (['inspect'],['port'],['logs','--tail','2000']):return args
        if len(args)==4 and args[:2]==['inspect','--format']:return args
    if args==['exec','woow-emqx','stat','-c','%a %U','/opt/emqx/etc/woow-mqtt-bootstrap.csv']:return args
    if args[:5] == ['secret','inspect','--showsecret','--format','{{.SecretData}}'] and len(args)==6 and args[-1] in ('woow-emqx-dashboard-password', 'woow-emqx-mqtt-password'):
        return args
    raise ValueError('not_a_reviewed_package_smoke_operation')


if __name__ == '__main__':
    try:
        result = guarded_args(sys.argv[1:], '/home/appowner/r4-smoke-tmp')
        os.execv('/usr/bin/podman', ['podman', *result])
    except Exception:
        print('fixture Podman operation refused', file=sys.stderr); raise SystemExit(97)
