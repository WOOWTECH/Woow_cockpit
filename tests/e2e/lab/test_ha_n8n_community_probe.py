import copy,io,json,unittest,urllib.error
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('ha_probe_driver', Path(__file__).with_name('ha_import_e2e.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
helper = {}
exec(driver.LOCAL_COMMUNITY_PROBE, helper)
local_community_probe = helper['local_community_probe']
PACKAGE, VERSION = helper['PACKAGE'], helper['VERSION']
DB={'package':PACKAGE,'version':VERSION,'nodes':[{'type':PACKAGE+'.globals','version':1}]}
MF={'name':PACKAGE,'version':VERSION,'node_files_valid':True}
class Response(io.BytesIO):
    status=200
class Opener:
    def __init__(self,body=None,error=None):self.body=body;self.error=error;self.calls=[]
    def open(self,request,timeout):
        self.calls.append(request.full_url)
        assert request.full_url=='http://127.0.0.1:15678/rest/node-types'
        assert request.method=='POST' and timeout==5
        assert json.loads(request.data)['nodeInfos']==[{'name':PACKAGE+'.globals','version':1}]
        if self.error:raise self.error
        return Response(json.dumps(self.body).encode())
class Tests(unittest.TestCase):
    def run_probe(self,db=None,mf=None,body=None,error=None):
        o=Opener(body if body is not None else {'data':[{'name':'globals','version':1}]},error)
        out=local_community_probe(o,{},lambda:(copy.deepcopy(DB if db is None else db),copy.deepcopy(MF if mf is None else mf)))
        return out,o
    def test_success_requires_runtime_response(self):
        out,o=self.run_probe();self.assertEqual(out['n8n_packages'],[[PACKAGE,VERSION,False]]);self.assertEqual(len(o.calls),1)
    def test_baseline_missing_package_fails_before_api(self):
        out,o=self.run_probe(db={});self.assertEqual(out['n8n_packages'],[]);self.assertEqual(o.calls,[])
    def test_bad_db_version_fails(self):
        x={**DB,'version':'9.9.9'};self.assertEqual(self.run_probe(db=x)[0]['n8n_packages'],[])
    def test_missing_files_fails(self):
        self.assertEqual(self.run_probe(mf={**MF,'node_files_valid':False})[0]['n8n_packages'],[])
    def test_zero_registered_nodes_fails(self):
        self.assertEqual(self.run_probe(db={**DB,'nodes':[]})[0]['n8n_packages'],[])
    def test_files_exist_but_runtime_node_missing_fails(self):
        self.assertEqual(self.run_probe(body={'data':[]})[0]['n8n_packages'],[])
    def test_wrong_runtime_identity_or_version_fails(self):
        for d in [{'name':'other','version':1},{'name':'globals','version':2}]:
            with self.subTest(d=d):self.assertEqual(self.run_probe(body={'data':[d]})[0]['n8n_packages'],[])
    def test_auth_and_timeout_fail_closed_without_secret_output(self):
        for err in [TimeoutError('SECRET_SENTINEL'),urllib.error.HTTPError('http://localhost',401,'SECRET_SENTINEL',{},None)]:
            out,_=self.run_probe(error=err);self.assertEqual(out['n8n_packages'],[]);self.assertNotIn('SECRET_SENTINEL',json.dumps(out))

class DeviceProbeTests(unittest.TestCase):
    def test_embedded_probe_avoids_registry_and_requires_runtime_loading(self):
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import subprocess
        # Exercise the complete shipped script, including login, inventory and HTTP routing.
        for loaded in (True, False):
            calls = []
            class Session:
                def open(self, request, timeout):
                    calls.append(request.full_url)
                    if request.full_url.endswith('/rest/login'):
                        body = {'data': {}}
                    elif request.full_url.endswith('/rest/credentials'):
                        body = {'data': [{'name': 'synthetic'}]}
                    elif request.full_url.endswith('/rest/node-types'):
                        body = {'data': [{'name': 'globals', 'version': 1}]} if loaded else {'data': []}
                    else:
                        raise TimeoutError('registry must not be consulted')
                    return Response(json.dumps(body).encode())
            request = {'local_community_probe': True, 'n8n': {
                'email': 'test@invalid', 'password': 'SYNTHETIC_ONLY', 'credential': 'synthetic'}}
            def command(argv, **kwargs):
                self.assertEqual(argv[:3], ['/usr/local/bin/woowbk-owner', 'podman', 'exec'])
                data = DB if argv[3] == 'n8n-postgres' else MF
                return subprocess.CompletedProcess(argv, 0, json.dumps(data).encode(), b'')
            output = io.StringIO()
            with patch('sys.stdin', io.StringIO(json.dumps(request))), \
                 patch('urllib.request.build_opener', return_value=Session()), \
                 patch('subprocess.run', side_effect=command), redirect_stdout(output):
                exec(driver.DEVICE_PROBE, {})
            result = json.loads(output.getvalue())
            self.assertTrue(result['n8n_login'])
            self.assertEqual(bool(result['n8n_packages']), loaded)
            self.assertFalse(any('community-packages' in url for url in calls))
            self.assertNotIn('SYNTHETIC_ONLY', output.getvalue())

    def test_isolation_refusal_prevents_device_exec(self):
        from unittest.mock import patch
        with patch.object(driver, 'require_isolated_device', side_effect=driver.Failed('isolated only')), \
             patch.object(driver, 'root') as root:
            with self.assertRaises(driver.Failed):
                driver.device_probe({})
            root.assert_not_called()

    def test_arm_wrapper_enables_local_probe(self):
        from unittest.mock import patch
        import subprocess
        with patch.object(driver, 'require_isolated_device'), \
             patch.dict(driver.EXPECT, arch='aarch64'), \
             patch.object(driver, 'root', return_value=subprocess.CompletedProcess([], 0, b'{}', b'')) as root:
            driver.device_probe({'n8n': {}})
        self.assertTrue(json.loads(root.call_args.kwargs['input'])['local_community_probe'])

if __name__=='__main__':unittest.main()

