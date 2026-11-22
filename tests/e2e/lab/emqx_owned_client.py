"""Invocation-labelled pinned Mosquitto container cleanup, never remove by name.

The caller uses yielded args on its NEW run. A run failure is not ownership
proof. Inspect requires the fresh label, full CID, exact name and fixed image;
foreign/unknown responses refuse without deletion. No raw inspect is exposed.
"""
from contextlib import contextmanager
import json
import re
import secrets

from emqx_adapter_mqtt import CLIENT
from emqx_private_boundary import PrivateFailure

LABEL = 'io.woowbackup.emqx.owner-client'
LIMIT = 65536


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError()
        result[key]=value
    return result


def _call(runner,*args,limit=4096):
    result=runner.podman(*args,timeout=5,max_output=limit,check=False)
    if (type(result.returncode) is not int or any(type(x) is not bytes or len(x)>limit
            for x in (result.stdout,result.stderr))):raise ValueError()
    return result


def _absent(runner,identity):
    result=_call(runner,'container','exists',identity)
    if result.returncode not in (0,1):raise ValueError()
    return result.returncode==1


def _cleanup(runner,name,nonce):
    try:
        if _absent(runner,name):return  # --rm already completed; no deletion.
        reply=_call(runner,'container','inspect',name,limit=LIMIT)
        if reply.returncode:
            if _absent(runner,name):return  # --rm raced inspect.
            raise ValueError()
        def invalid(_):raise ValueError()
        rows=json.loads(reply.stdout,object_pairs_hook=_pairs,parse_constant=invalid)
        if type(rows) is not list or len(rows)!=1 or type(rows[0]) is not dict:raise ValueError()
        doc=rows[0];cid=doc.get('Id')
        if (type(cid) is not str or re.fullmatch('[0-9a-f]{64}',cid) is None
                or doc.get('Name')!='/'+name or type(doc.get('Image')) is not str
                or doc['Image'] not in (CLIENT,CLIENT.removeprefix('sha256:'))
                or type(doc.get('Config')) is not dict or type(doc['Config'].get('Labels')) is not dict
                or doc['Config']['Labels'].get(LABEL)!=nonce):raise ValueError()
        if _call(runner,'rm','--force','--ignore',cid).returncode:raise ValueError()
        if not _absent(runner,cid) or not _absent(runner,name):raise ValueError()
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('owned-client-cancelled') from None
    except Exception:raise PrivateFailure('owned-client-refused') from None


@contextmanager
def owned_client(runner,name):
    """with owned_client(runner,name) as args: runner.podman('run',*args,...).

    Exact bounded owner namespace; --name and fresh 256-bit nonce label supplied
    together. No existing client is adopted. Runner must bound IO and processes.
    Cleanup on every exit inspects by name, deletes ONLY proven full CID, then
    proves CID/name absence. Unknown ownership is a refusal, never a deletion.
    """
    try:
        if (not callable(getattr(runner,'podman',None)) or type(name) is not str
                or re.fullmatch(r'woowbk-emqxlab-[0-9a-f]{8}-(?:mqtt|negative)-[0-9a-f]{12}',name) is None
                or not _absent(runner,name)):raise ValueError()
        nonce=secrets.token_hex(32)
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('owned-client-cancelled') from None
    except Exception:raise PrivateFailure('owned-client-refused') from None
    try:
        yield ('--name',name,'--label',LABEL+'='+nonce)
    finally:
        _cleanup(runner,name,nonce)
