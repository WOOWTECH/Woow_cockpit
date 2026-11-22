"""Explicit owner profile for one pinned-image vendor ACL dependency.

No host environment/path resolution, archive etc files, or implied default path.
The trusted observer is fixed code; callers cannot supply a dependency reader.
This is private value collection, not an ACL policy/restore approval.
"""
import base64
import hashlib
import json
from pathlib import Path
import tempfile

from emqx_native_runtime import IMAGE, run_native
from emqx_semantic_readers import (
    Values, MAX_VALUE, MAX_OUTPUT, SemanticRefused, _contract, _json_walk,
    _text, _term, _pairs, refuse,
)

class OwnerFileRefused(SemanticRefused):
    def __init__(self,phase):
        super().__init__()
        self.phase=phase if phase in ('profile','contract','document','walk','file_location','file_path','file_key','scalar','syntax','vendor_observer','receipt','register') else 'contract'

PROFILE = 'owner-pinned-image-vendor-acl-v1'
LITERAL = '${EMQX_ETC_DIR}/acl.conf'
VENDOR_PATH = '/opt/emqx/etc/acl.conf'
SCRIPT = Path(__file__).with_name('emqx_vendor_acl.escript')


def observe_vendor_acl():
    """Observe the whole regular file in the cached pinned image, never a broker.

    Uses existing networkless native runner:256MiB RAM,64 PIDs,10 CPU seconds,
    15s container/20s client limit, no pulls, host data or production mounts.
    Caller must explicitly invoke this profile; normal read_hocon never calls it.
    """
    try:
        with tempfile.TemporaryDirectory(prefix='emqx-vendor-acl-private-') as directory:
            script = Path(directory) / SCRIPT.name
            script.write_bytes(SCRIPT.read_bytes())
            script.chmod(0o600)
            with tempfile.TemporaryFile() as output:
                status = run_native(directory, SCRIPT.name, output=output)
                output.seek(0)
                encoded = output.read(MAX_OUTPUT + 1)
            if status or not encoded or len(encoded) > MAX_OUTPUT:
                refuse()
            doc = json.loads(encoded, object_pairs_hook=_pairs,
                             parse_constant=lambda _: refuse())
            if (type(doc) is not dict or set(doc) != {'contract', 'content_b64', 'terms'}
                    or doc['contract'] != 'emqx-vendor-acl-v1'
                    or type(doc['content_b64']) is not str or type(doc['terms']) is not list):
                refuse()
            raw = base64.b64decode(doc['content_b64'], validate=True)
            if (not 0 < len(raw) <= MAX_VALUE
                    or base64.b64encode(raw).decode() != doc['content_b64']):
                refuse()
            values = Values()
            if not doc['terms']:
                refuse()
            for term in doc['terms']:
                _term(term, values, historical=True)
            # The runner, not archive metadata, fixes the image and path.
            return raw, {'image': IMAGE, 'path': VENDOR_PATH,
                         'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                         'complete': True, 'regular': True}, values.values
    except Exception:
        raise SemanticRefused() from None


class OwnerFileValues(Values):
    def __init__(self):
        super().__init__()
        self.file_receipts = ()


def read_owner_file_hocon(raw, parser=None, *, profile, product_image):
    """Full native HOCON values plus complete vendor ACL bytes and receipt.

    Explicit image identity must equal the native runner's immutable pin. Only
    authorization.sources[*].type=file with an explicit fixed literal is accepted.
    Native syntax_strings are retained; substitutions/includes still refuse.
    Default read_hocon remains wholly strict. Unknown/missing paths never read IO.
    """
    stage='profile'
    try:
        if profile != PROFILE or product_image != IMAGE:
            refuse()
        stage='contract'
        doc = _contract(raw, parser, 'emqx-hocon-json-v1')
        if (set(doc) != {'contract', 'version', 'input_sha256', 'input_bytes',
                         'complete', 'resolution', 'references', 'document'}
                or doc['resolution'] != 'disabled' or doc['references'] != []):
            refuse()
        stage='document'
        document = doc['document']
        # Require the actual native adapter's full effective map AND syntax leaves.
        if (type(document) is not dict or set(document) != {'parsed', 'syntax_strings'}
                or type(document['parsed']) is not dict
                or type(document['syntax_strings']) is not list
                or any(type(s) is not str for s in document['syntax_strings'])):
            refuse()
        result = OwnerFileValues()
        dependencies = []

        def walk(value, location=(), depth=0):
            nonlocal stage
            stage='walk'
            if type(value) not in (dict, list):
                stage='scalar'
                _json_walk(value, result, depth)
                return
            result.tick(depth)
            if type(value) is list:
                for index, child in enumerate(value):
                    walk(child, location + (index,), depth + 1)
                return
            file_source = value.get('type') == 'file'
            if file_source:
                stage='file_location'
                if (len(location) != 3 or location[:2] != ('authorization', 'sources')
                        or type(location[2]) is not int or value.get('path') != LITERAL):
                    refuse()
                dependencies.append(location)
            for key, child in value.items():
                result.add(_text(key))
                stage='file_key'
                if (key in ('certfile', 'keyfile', 'cacertfile', 'bootstrap_file', 'init_file')
                        or key.endswith('_file')) and child:
                    refuse()
                if file_source and key == 'path':
                    result.tick(depth + 1)
                    result.add(_text(child))
                else:
                    walk(child, location + (key,), depth + 1)

        walk(document['parsed'])
        # No unneeded image reads, and no bare literal exception without a source.
        if not dependencies:
            refuse()
        stage='syntax'
        for value in document['syntax_strings']:
            if value == LITERAL:
                result.tick(1)
                result.add(_text(value))
            else:
                _json_walk(value, result, 1)
        stage='vendor_observer'
        content, receipt, acl_values = observe_vendor_acl()
        stage='receipt'
        if (type(content) is not bytes or not 0 < len(content) <= MAX_VALUE
                or type(receipt) is not dict or receipt != {
                    'image': IMAGE, 'path': VENDOR_PATH, 'bytes': len(content),
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'complete': True, 'regular': True}):
            refuse()
        stage='register'
        result.add(content)
        for value in acl_values:
            result.add(value)
        result.file_receipts = (dict(receipt),)
        return result
    except Exception:
        raise OwnerFileRefused(stage) from None
