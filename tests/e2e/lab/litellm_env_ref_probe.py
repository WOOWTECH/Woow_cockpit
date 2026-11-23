"""LiteLLM HA import security review, iteration 2 (SR-7): does a DATABASE model row whose api_key is
`os.environ/LITELLM_MASTER_KEY` make LiteLLM 1.104.0 send this device's master key to the row's api_base?

Runs INSIDE a throwaway container of the package's LiteLLM image with --network=none (stdin script; see
litellm_env_ref_probe.sh). The vendor's own DB-model path is used: ProxyConfig._add_deployment (decrypt each
litellm_params value, then resolve os.environ/ references, proxy_server.py:7119-7166) into a Router, then one
chat completion through that Router. The "provider" is a local HTTP server on 127.0.0.1 inside the same container
that compares the Authorization header with the generated canary master key and keeps only the verdict.
Output: one JSON line of verdicts (no canary, no key value)."""
import asyncio
import json
import os
import secrets
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer

CANARY = 'sk-woowbk-canary-master-' + secrets.token_hex(16)  # generated here, never printed
os.environ['LITELLM_MASTER_KEY'] = CANARY
os.environ['LITELLM_SALT_KEY'] = 'sk-woowbk-salt-' + secrets.token_hex(16)  # the "moved" HA salt (test value)
SEEN = {}


class Provider(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get('content-length') or 0)
        self.rfile.read(length)
        auth = self.headers.get('authorization') or ''
        SEEN.setdefault(self.path, []).append({'bearer_is_device_master_key': auth == f'Bearer {CANARY}',
                                               'bearer_present': auth.startswith('Bearer ')})
        body = json.dumps({'id': 'x', 'object': 'chat.completion', 'created': 0, 'model': 'woowbk',
                           'choices': [{'index': 0, 'finish_reason': 'stop',
                                        'message': {'role': 'assistant', 'content': 'ok'}}],
                           'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


async def main():
    server = HTTPServer(('127.0.0.1', 18099), Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    import litellm
    from litellm.proxy import proxy_server
    from litellm.proxy.common_utils.encrypt_decrypt_utils import encrypt_value_helper

    proxy_server.llm_router = litellm.Router(model_list=[])
    config = proxy_server.ProxyConfig()
    rows = {
        # what HA's LiteLLM_ProxyModelTable could hold: the reference in plaintext (a value that does not decrypt is
        # used as it is) and encrypted with HA's salt (how /model/new stores it)
        'plaintext_reference': 'os.environ/LITELLM_MASTER_KEY',
        'encrypted_reference': encrypt_value_helper('os.environ/LITELLM_MASTER_KEY'),
    }
    out = {'litellm_version': getattr(litellm, 'version', None) or 'unknown', 'cases': {}}
    for name, api_key in rows.items():
        model = types.SimpleNamespace(
            model_name=f'woowbk-{name}', model_id=f'woowbk-{name}', model_info={'id': f'woowbk-{name}'},
            litellm_params={'model': 'openai/woowbk', 'api_base': f'http://127.0.0.1:18099/{name}/v1',
                            'api_key': api_key})
        added = config._add_deployment(db_models=[model])
        try:
            await proxy_server.llm_router.acompletion(model=f'woowbk-{name}',
                                                      messages=[{'role': 'user', 'content': 'hi'}])
            error = None
        except Exception as exc:  # noqa: BLE001 - recorded as the class name only
            error = type(exc).__name__
        seen = SEEN.get(f'/{name}/v1/chat/completions', [])
        out['cases'][name] = {'added': added, 'error': error, 'requests': len(seen),
                              'device_master_key_sent': any(s['bearer_is_device_master_key'] for s in seen),
                              'bearer_present': any(s['bearer_present'] for s in seen)}
    server.shutdown()
    text = json.dumps(out, sort_keys=True)
    assert CANARY not in text
    print(text)


asyncio.run(main())
