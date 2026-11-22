"""Private Mosquitto2.0 config transport for the synthetic adapter only."""
import os
from pathlib import Path
import re
import secrets
import tempfile

CLIENT = 'sha256:93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3'


def mqtt(runner, broker, program, topic, payload=None, *, username, credential, clear=False):
    """No credentials in argv/env; one named invocation, cleanup even on timeout.

    Config is discovered by Mosquitto via fixed HOME/XDG_CONFIG_HOME, as in the
    broker workload. Bind mounts use the current owner's keep-id mapping.
    Returned output stays private with the caller; no diagnostics are emitted.
    """
    if (not re.fullmatch(r'woowbk-emqxlab-[0-9a-f]{8}', broker)
            or program not in ('mosquitto_pub', 'mosquitto_sub')
            or not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', username)
            or not isinstance(credential, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', credential)
            or type(clear) is not bool or (clear and (payload is not None or program != 'mosquitto_pub'))
            or (program == 'mosquitto_sub' and payload is not None)):
        raise RuntimeError('private-mqtt-refused')
    client = broker + '-mqtt-' + secrets.token_hex(6)
    owned = False
    with tempfile.TemporaryDirectory(prefix=client + '-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        for command in ('mosquitto_pub', 'mosquitto_sub'):
            descriptor = os.open(root / command, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, 'w') as config:
                config.write('-u ' + username + '\n-P ' + credential + '\n')
        try:
            if runner.podman('container', 'exists', client, check=False, timeout=10).returncode != 1:
                raise RuntimeError('private-mqtt-name-refused')
            owned = True  # run may create the container before a failure/timeout.
            argv = ['run', '--rm', '--name', client, '--pull=never',
                    '--log-driver=none', '--image-volume=ignore',
                    '--network=container:' + broker,
                    '--userns=keep-id:uid=1000,gid=1000', '--user=1000:1000',
                    '--memory=64m', '--cpus=0.25', '--pids-limit=32',
                    '--timeout=15', '--stop-timeout=1',
                    '-e', 'HOME=/work', '-e', 'XDG_CONFIG_HOME=/work',
                    '-v', str(root) + ':/work:ro', '--entrypoint=' + program, CLIENT,
                    '-h', '127.0.0.1', '-p', '1883', '-V', 'mqttv5', '-q', '1',
                    '-i', client, '-t', topic]
            if clear:
                argv += ['-r', '-n', '-d']
            elif payload is not None:
                argv += ['-r', '-m', payload, '-d']
            else:
                argv += ['-C', '1', '-W', '10']
            return runner.podman(*argv, timeout=20, check=False, max_output=65536)
        finally:
            if owned:
                removed = absent = False
                try:
                    removed = runner.podman('rm', '--force', '--ignore', client,
                        check=False, timeout=10, max_output=4096).returncode == 0
                except Exception:
                    pass
                try:
                    absent = runner.podman('container', 'exists', client,
                        check=False, timeout=10, max_output=4096).returncode == 1
                except Exception:
                    pass
                if not removed or not absent:
                    raise RuntimeError('private-mqtt-cleanup-refused') from None
