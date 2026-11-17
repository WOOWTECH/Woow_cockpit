import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('parallel_renderer',ROOT/'parallel-ingress/render.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
# The standalone manager imports its neighboring renderer.
with patch.dict(sys.modules,{'render':r}):
    spec=importlib.util.spec_from_file_location('parallel_manager',ROOT/'parallel-ingress/manage.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture_config():
    return dict(schema=1,instance='apporo',brand='apporo',owner='operator',public_origin='https://apporo.example.test',
                listen_port=29092,compatibility_port=18000,pi_public_port=19096,pi_local_port=19097)


class ParallelIngress(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'host';self.out=Path(self.tmp.name)/'output'
        p=self.root/'var/lib/dpkg/status';p.parent.mkdir(parents=True)
        p.write_text('Package: cockpit-bridge\nStatus: install ok installed\nVersion: 362-1\n\n')
        desired,state=r.manage.desired_files(self.root)
        r.manage.install(self.root,desired,state)
        p=self.root/'usr/local/share/cockpit/woowpiweb/manifest.json';p.parent.mkdir(parents=True)
        p.write_text('{}')

    def test_complete_overlay_uses_same_backends_and_keeps_schedule_ui(self):
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        hashes=r.render(fixture_config(),self.out,self.root)
        self.assertGreater(len(hashes),20)
        backup=self.out/'public/packages/woowtechbackup/backup.js'
        self.assertIn('schedule-set',backup.read_text())
        for name in ('index.html','gallery.css','gallery.js','layout-review.html','layout-review.css','assets/mdi-icons.js','assets/logo-lockup-blue.svg'):
            self.assertTrue((self.out/'public/packages/woowtechpreview'/name).is_file(),name)
        for name in ('index.html','style.css','app.js','manifest.json'):
            self.assertTrue((self.out/'public/packages/woowpiweb'/name).is_file())
        js=(self.out/'public/packages/woowpiweb/app.js').read_text()
        self.assertNotIn('__PUBLIC_ORIGIN__',js)
        self.assertIn('https://apporo.example.test',js)
        self.assertIn('http://127.0.0.1:29092',js)
        css=(self.out/'public/packages/woowpiweb/style.css').read_text()
        self.assertNotIn('#6183fc',css.lower())
        self.assertNotIn('#3f63e8',css.lower())
        self.assertIn('--brand-primary: #C49E53',css)
        self.assertIn('font-family: var(--brand-font)',css)
        css=(self.out/'public/branding/branding.css').read_text()
        self.assertIn('html:root.pf-v6-theme-dark',css)
        self.assertIn('--pf-t--global--font--family--body: var(--brand-font)',css)
        self.assertIn('/favicon.ico?v=',(self.out/'public/pwa/assets/brand-ui.js').read_text())
        for name in ('index.html','layout-review.html'):
            html=(self.out/'public/packages/woowtechpreview'/name).read_text()
            self.assertNotIn('src="screenshots/',html)
            self.assertNotIn('src="layout-images/',html)
            self.assertIn('尚未建立此設備的畫面紀錄',html)
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_backend_drift_stops_before_generating_output(self):
        p=self.root/r.manage.BACKUP_HELPER;p.write_bytes(p.read_bytes()+b'\n# drift')
        with self.assertRaisesRegex(ValueError,'common backend differs'):
            r.render(fixture_config(),self.out,self.root)
        self.assertFalse(self.out.exists())

    def test_unexpected_module_and_missing_registered_package_rejected(self):
        p=self.root/r.manage.BACKUP_ENGINE/'extra.py';p.write_text('')
        with self.assertRaisesRegex(ValueError,'modules differ'):r.backend_hashes(self.root)
        p.unlink();(self.root/'usr/local/share/cockpit/woowpiweb/manifest.json').unlink()
        with self.assertRaisesRegex(ValueError,'common Cockpit package'):r.backend_hashes(self.root)

    def test_invalid_origin_ports_and_names_rejected(self):
        for key,value in [('public_origin','https://good.test; return 200;'),('public_origin','http://public.test'),
                          ('public_origin','https://user:secret@example.test'),('public_origin','https://example.test/path'),
                          ('instance','../other'),('instance','woow'),('owner','root'),('image','nginx:latest'),
                          ('node_path','/home/operator/node'),('listen_port',9090),('schema',True)]:
            with self.subTest(key=key,value=value):
                c=fixture_config();c[key]=value
                with self.assertRaises(ValueError):r.config(c)

    def test_origin_allowlist_is_additive_and_never_forges_origin(self):
        original='[WebService]\nOrigins = https://old.example.test\nAllowUnencrypted = true\n[Session]\nIdleTimeout = 0\n'
        updated=m.origins(original,['https://apporo.example.test','http://127.0.0.1:29092'])
        self.assertIn('https://old.example.test',updated)
        self.assertIn('AllowUnencrypted = true\n[Session]\nIdleTimeout = 0',updated)
        self.assertEqual(updated,m.origins(updated,['https://apporo.example.test']))
        nginx=r.nginx(r.config(fixture_config()))
        self.assertIn('proxy_set_header Origin $http_origin;',nginx)
        self.assertNotIn('cockpit-openclaw',nginx)
        self.assertIn('auth_request /__parallel_auth;',nginx)
        self.assertIn("add_header Cache-Control 'no-store'",nginx)
        for path in ('favicon.ico','apple-touch-icon.png','brand.json','mobile-navigation.js'):
            self.assertIn('location = /cockpit/static/'+path,nginx)
        self.assertIn('/branding/assets/logo-symbol-blue.svg',nginx)

    def test_separate_private_pi_services_and_public_static_root(self):
        c=r.config(fixture_config())
        for mode in ('local','public'):
            unit=r.pi_unit(c,mode)
            self.assertIn('DynamicUser=yes',unit)
            self.assertIn(f"PI_GATEWAY_PORT={c['pi_'+mode+'_port']}",unit)
            self.assertIn('PI_GATEWAY_BRAND_FILE=/etc/cockpit/parallel-ingress/apporo/current/public/branding/brand.json',unit)
        q=r.quadlet(c,Path('/etc/cockpit/parallel-ingress/apporo/releases/fixture'))
        self.assertIn('ContainerName=apporo-cockpit-pwa',q)
        self.assertIn('/public:/opt/parallel/public:ro',q)
        self.assertNotIn('/home/',q)


if __name__=='__main__':unittest.main()
