"""Generated Podman process contracts only; no container or lab access."""
import copy
import io
import json
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
import unittest

import emqx_owned_client as m
from emqx_private_boundary import PrivateFailure


class Runner:
    def __init__(self):
        self.name='woowbk-emqxlab-1234abcd-mqtt-123456abcdef'
        self.cid='a'*64;self.doc=None;self.calls=[];self.wire=None
        self.inspect_error=False;self.auto_remove=False;self.rm_error=False
        self.replace_after_inspect=False

    def podman(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        limit=m.LIMIT if args[:2]==('container','inspect') else 4096
        assert kwargs==dict(timeout=5,max_output=limit,check=False)
        if args[:2]==('container','exists'):
            exists=self.doc is not None and args[2] in (self.name,self.doc['Id'])
            return SimpleNamespace(returncode=0 if exists else 1,stdout=b'',stderr=b'')
        if args[:2]==('container','inspect'):
            raw=self.wire if self.wire is not None else json.dumps([self.doc]).encode()
            if self.auto_remove:self.doc=None
            if self.replace_after_inspect:
                self.doc=copy.deepcopy(self.doc);self.doc['Id']='b'*64
                self.doc['Config']['Labels']={m.LABEL:'foreign-label'}
            return SimpleNamespace(returncode=125 if self.inspect_error else 0,stdout=raw,stderr=b'generated-private-diagnostic')
        assert args==('rm','--force','--ignore',self.cid),args
        if self.doc is not None and self.doc['Id']==self.cid:self.doc=None
        return SimpleNamespace(returncode=1 if self.rm_error else 0,stdout=self.cid.encode(),stderr=b'')

    def create(self,args):
        assert args[:3]==('--name',self.name,'--label')
        label,nonce=args[3].split('=',1)
        self.doc={'Id':self.cid,'Name':'/'+self.name,'Image':m.CLIENT,
                  'Config':{'Labels':{label:nonce},'Env':['PRIVATE=generated-private-secret']}}


class OwnedClientTests(unittest.TestCase):
    def setUp(self):self.r=Runner()
    def removals(self):return [a for a,k in self.r.calls if a[0]=='rm']

    def test_owned_label_cid_and_image_cleanup_only_by_full_cid(self):
        with m.owned_client(self.r,self.r.name) as args:
            self.r.create(args)
        self.assertEqual(self.removals(),[('rm','--force','--ignore',self.r.cid)])
        self.assertIsNone(self.r.doc)
        self.assertEqual(self.r.calls[-2][0],('container','exists',self.r.cid))
        self.assertEqual(self.r.calls[-1][0],('container','exists',self.r.name))

    def test_exact_name_without_leading_slash_is_owned_podman_spelling(self):
        with m.owned_client(self.r,self.r.name) as args:
            self.r.create(args)
            self.r.doc['Name']=self.r.name
        self.assertEqual(self.removals(),[('rm','--force','--ignore',self.r.cid)])
        self.assertIsNone(self.r.doc)

    def test_exact_rawhex_image_spelling_and_new_nonce_per_invocation(self):
        nonces=[]
        for _ in range(2):
            with m.owned_client(self.r,self.r.name) as args:
                nonces.append(args[-1]);self.r.create(args)
                self.r.doc['Image']=m.CLIENT.removeprefix('sha256:')
        self.assertNotEqual(*nonces)
        self.assertRegex(nonces[0].split('=',1)[1],r'^[0-9a-f]{64}$')

    def test_already_auto_removed_and_racing_inspect_absence_need_no_rm(self):
        with m.owned_client(self.r,self.r.name):pass
        self.assertEqual(self.removals(),[])
        self.r.inspect_error=True;self.r.auto_remove=True
        with m.owned_client(self.r,self.r.name) as args:self.r.create(args)
        self.assertEqual(self.removals(),[])

    def test_foreign_label_collision_after_prepare_refuses_without_delete(self):
        with self.assertRaisesRegex(PrivateFailure,'^owned-client-refused$'):
            with m.owned_client(self.r,self.r.name) as args:
                self.r.create(args);self.r.doc['Config']['Labels'][m.LABEL]='foreign-label'
        self.assertEqual(self.removals(),[]);self.assertIsNotNone(self.r.doc)

    def test_preexisting_foreign_name_is_never_adopted_or_removed(self):
        self.r.doc={'Id':'b'*64}
        with self.assertRaisesRegex(PrivateFailure,'^owned-client-refused$'):
            with m.owned_client(self.r,self.r.name):self.fail('must not yield')
        self.assertEqual(self.removals(),[])

    def test_wrong_name_image_cid_or_labels_never_delete(self):
        for edit in (lambda d:d.update(Name='//'+self.r.name),lambda d:d.update(Image='0'*64),
                     lambda d:d.update(Image='other:'+m.CLIENT),lambda d:d.update(Id='short'),
                     lambda d:d['Config'].update(Labels={}),lambda d:d['Config'].update(Labels=[])):
            self.r.calls.clear()
            with self.assertRaisesRegex(PrivateFailure,'^owned-client-refused$'):
                with m.owned_client(self.r,self.r.name) as args:self.r.create(args);edit(self.r.doc)
            self.assertEqual(self.removals(),[]);self.r.doc=None

    def test_malformed_duplicate_oversize_and_private_inspect_output_never_escape(self):
        for raw in (b'generated-private-secret',b'[]',b'[{},{}]',b'[{"Id":"a","Id":"b"}]',b'x'*(m.LIMIT+1)):
            self.r.wire=raw;self.r.calls.clear();self.r.doc=None
            stdout,stderr=io.StringIO(),io.StringIO()
            with redirect_stdout(stdout),redirect_stderr(stderr):
                with self.assertRaisesRegex(PrivateFailure,'^owned-client-refused$') as caught:
                    with m.owned_client(self.r,self.r.name) as args:self.r.create(args)
            self.assertEqual(str(caught.exception),'owned-client-refused')
            self.assertEqual(stdout.getvalue()+stderr.getvalue(),'');self.assertEqual(self.removals(),[])

    def test_name_replacement_after_inspect_does_not_remove_replacement(self):
        self.r.replace_after_inspect=True
        with self.assertRaisesRegex(PrivateFailure,'^owned-client-refused$'):
            with m.owned_client(self.r,self.r.name) as args:self.r.create(args)
        self.assertEqual(self.removals(),[('rm','--force','--ignore',self.r.cid)])
        self.assertEqual(self.r.doc['Id'],'b'*64)

    def test_body_failure_still_cleans_proven_owned_cid(self):
        with self.assertRaises(TimeoutError):
            with m.owned_client(self.r,self.r.name) as args:
                self.r.create(args);raise TimeoutError()
        self.assertIsNone(self.r.doc);self.assertEqual(len(self.removals()),1)

    def test_remove_failure_refuses_even_if_absent(self):
        self.r.rm_error=True
        with self.assertRaisesRegex(PrivateFailure,'^owned-client-refused$'):
            with m.owned_client(self.r,self.r.name) as args:self.r.create(args)


if __name__=='__main__':unittest.main()
