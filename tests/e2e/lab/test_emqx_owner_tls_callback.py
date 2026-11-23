"""Proved callback metadata -> exact target consumer; no callback/module execution."""
import base64
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest

from emqx_owner_target import owner_target_readers
from emqx_private_boundary import PrivateFailure
from emqx_target_capture import TargetCaptureUnsupported
from test_emqx_owner_target import reply_document,typed

ROOT=Path(__file__).parent


def merge_native(target,source):
    entries={k['value']:v for k,v in target['value']}
    for k,v in source['value']:
        if k['value'] in entries and v['type']=='map' and entries[k['value']]['type']=='map':
            merge_native(entries[k['value']],v)
        else:
            target['value'].append([copy.deepcopy(k),copy.deepcopy(v)])


class TlsCallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-tls-callback-') as directory:
            root=Path(directory)
            for name in ('emqx_owner_tls_callback_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes());(root/name).chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code=run_native(root,'emqx_owner_tls_callback_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output)
                output.seek(0);raw=output.read(1048577)
                if code or len(raw)>1048576:
                    raise AssertionError('public inert callback fixture failed')
                cls.native=json.loads(raw)

    @contextmanager
    def quiesce(self):
        yield

    def transport(self,edit=None):
        def evaluate(expression):
            nonce=re.search(r'generation => <<"([0-9a-f]{32})">>',expression)[1]
            doc=reply_document(nonce)
            merge_native(doc['config'],self.native)
            doc['contract']='emqx-owner-live-target-v2'
            doc['config_secret_wrappers']=typed([])
            if edit: edit(doc)
            return b'WOOWTARGET:'+base64.b64encode(json.dumps(doc).encode())+b':ENDok'
        return evaluate

    def test_generated_native_identity_provenance_is_privately_scanned(self):
        with owner_target_readers(private_eval=self.transport(),quiesce=self.quiesce) as readers:
            self.assertEqual(len(readers),5)
            for value in (b'emqx_tls_psk',b'lookup',b'F2653DFD1072A73E2E6FEC1D77865D1F',
                b'DE702B30F75648B1435B584233503E51347F769A39B94DC5A2237781179633D6'):
                with self.assertRaises(PrivateFailure): readers.persisted_values.scan(value)

    def test_tls_enabled_still_refuses(self):
        def edit(doc):
            listeners=next(v for k,v in doc['config']['value'] if k['value']=='listeners')
            ssl=next(v for k,v in listeners['value'] if k['value']=='ssl')
            default=ssl['value'][0][1]
            for pair in default['value']:
                if pair[0]['value']=='enable': pair[1]=typed(True)
        with self.assertRaises(TargetCaptureUnsupported):
            with owner_target_readers(private_eval=self.transport(edit),quiesce=self.quiesce): pass
