"""Appended to PROBE_COMMON inside a NEW disposable runner container only.

Network observers return real responses unchanged. Production login/ensure/CLI
storage functions execute; only synthetic stored expiry is forced into the past.
No runner daemon, model, Pi process or existing workspace is started/changed.
"""
import hashlib
import httpx
import io
import os
from pathlib import Path
import runpy
import time
import urllib.request
from omnigent import cli_auth

server = 'http://127.0.0.1:8000'
os.environ['OMNIGENT_SERVER_URL'] = server
os.environ['OMNIGENT_RUNNER_USERNAME'] = REQ['username']
os.environ['OMNIGENT_RUNNER_PASSWORD'] = REQ['password']
real_urlopen = urllib.request.urlopen
real_post = httpx.post
calls = []
last_refresh = {}

def observe_login(request, *args, **kwargs):
    if request.full_url != server + '/auth/login':
        raise RuntimeError('unexpected login route')
    with real_urlopen(request, *args, **kwargs) as response:
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise RuntimeError('response too large')
        payload = json.loads(body)
        emit('auth', source='/auth/login', status=response.status,
             credentials={k: payload[k] for k in ('token', 'refresh_token') if k in payload})
        calls.append('login')
    return io.BytesIO(body)

def observe_refresh(url, *args, **kwargs):
    if url != server + '/oauth/token':
        raise RuntimeError('unexpected refresh route')
    response = real_post(url, *args, **kwargs)
    if len(response.content) > 1024 * 1024:
        raise RuntimeError('response too large')
    payload = response.json()
    emit('auth', source='/oauth/token', status=response.status_code,
         credentials={k: payload[k] for k in ('access_token', 'refresh_token') if k in payload})
    last_refresh.update(payload)
    calls.append('refresh')
    return response

urllib.request.urlopen = observe_login
httpx.post = observe_refresh
runner_path = Path('/usr/local/bin/omnigent-runner-login')
runner = runpy.run_path(str(runner_path), run_name='synthetic_probe')
runner['login'].__globals__['say'] = lambda _message: None
assert runner['login'](server) == 0
before = cli_auth._load_entry(server)
assert before and before.get('refresh_token') and before.get('token')
assert runner['ensure'](server) == 0 and calls == ['login']
# Mutate only this new container's synthetic credential expiry using CLI storage.
cli_auth.store_token(server, before['token'], before['user_id'], time.time() - 1,
                     refresh_token=before['refresh_token'])
time.sleep(1.1)
assert runner['ensure'](server) == 0
assert calls == ['login', 'refresh']  # no fallback login accepted
current = cli_auth._load_entry(server)
assert current['token'] == last_refresh['access_token']
assert current['refresh_token'] == last_refresh['refresh_token']
assert current['expires_at'] > time.time()
assert runner['ensure'](server) == 0 and calls == ['login', 'refresh']
finish({'probe':'real-runner-login-ensure', 'good_token_no_request':True,
        'expired_token_refreshed':True, 'fallback_login':False, 'stored_grant_verified':True,
        'runner_coverage':False, 'scope':'one controlled ensure cycle only',
        'runner_script_sha256':hashlib.sha256(runner_path.read_bytes()).hexdigest(),
        'cli_auth_sha256':hashlib.sha256(Path(cli_auth.__file__).read_bytes()).hexdigest()})
