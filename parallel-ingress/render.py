#!/usr/bin/env python3
"""Build a second branded entrance to an existing Cockpit, without installing engines."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from scripts import manage, brand_profile

IMAGE = 'docker.io/nginxinc/nginx-unprivileged@sha256:5aea7cc516b419e3526f47dd1531be31a56a046cfe44754d94f9383e13e2ee99'
BASE = '/etc/cockpit/parallel-ingress'
PREFIXES = {manage.BRAND: 'branding', manage.PREVIEW: 'packages/woowtechpreview',
            manage.SERVICES: 'packages/woowtechservices', manage.APPS: 'packages/woowtechapps',
            manage.BACKUP_UI: 'packages/woowtechbackup'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def config(raw):
    defaults = dict(cockpit_port=9090, pi_upstream_port=30141, compatibility_port=None,
                    node_path='/usr/bin/node', image=IMAGE)
    required = {'schema', 'instance', 'brand', 'owner', 'public_origin', 'listen_port',
                'pi_public_port', 'pi_local_port'}
    if not isinstance(raw, dict) or not required <= raw.keys() or set(raw) - required - defaults.keys():
        raise ValueError('Invalid parallel ingress configuration fields')
    c = {**defaults, **raw}
    if type(c['schema']) is not int or c['schema'] != 1 or c['brand'] not in brand_profile.BRANDS:
        raise ValueError('Invalid parallel ingress schema/brand')
    if not isinstance(c['instance'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', c['instance']):
        raise ValueError('Invalid instance name')
    if c['instance'] == 'woow':
        raise ValueError('The existing woow-cockpit-pwa instance is reserved')
    if not isinstance(c['owner'], str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', c['owner']) or c['owner'] == 'root':
        raise ValueError('Use an existing non-root service owner')
    if not isinstance(c['public_origin'], str):
        raise ValueError('public_origin must be a string')
    u = urlsplit(c['public_origin'])
    if (u.scheme != 'https' or c['public_origin'] != 'https://'+u.netloc or u.path or u.query or u.fragment or u.username or u.password
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', u.netloc)):
        raise ValueError('public_origin must be an exact HTTPS DNS origin')
    ports = [c[k] for k in ('listen_port','pi_public_port','pi_local_port','cockpit_port','pi_upstream_port')]
    if c['compatibility_port'] is not None:
        ports.append(c['compatibility_port'])
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports) or len(ports) != len(set(ports)):
        raise ValueError('Ports must be distinct integers from 1024 to 65535')
    if c['node_path'] not in ('/usr/bin/node', '/usr/local/lib/woow-node/node'):
        raise ValueError('Use an approved root-owned Node executable')
    if not isinstance(c['image'], str) or not re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}', c['image']):
        raise ValueError('The gateway image must use an immutable registry digest')
    return c


def backend_hashes(root=Path('/')):
    """Refuse a UI from another engine revision, including unexpected Python modules."""
    pairs = {manage.HELPER: SOURCE / 'services/service-manager.py',
             manage.BACKUP_HELPER: SOURCE / 'backup-engine/woowtech-cockpit-backup'}
    engine = SOURCE / 'backup-engine/woowbackup'
    pairs.update({manage.BACKUP_ENGINE + '/' + p.relative_to(engine).as_posix(): p for p in engine.rglob('*.py')})
    installed = root / manage.BACKUP_ENGINE
    expected_modules = {n[len(manage.BACKUP_ENGINE)+1:] for n in pairs if n.startswith(manage.BACKUP_ENGINE+'/')}
    if {p.relative_to(installed).as_posix() for p in installed.rglob('*.py')} != expected_modules:
        raise ValueError('Installed backup engine modules differ from this source; align the common backend first')
    result = {}
    for name, src in pairs.items():
        dest = root / name
        if dest.is_symlink() or not dest.is_file() or dest.read_bytes() != src.read_bytes():
            raise ValueError('Installed common backend differs from this source: ' + name)
        result[name] = digest(src.read_bytes())
    for name in ('woowtechapps','woowtechbackup','woowtechservices','woowtechpreview','woowpiweb'):
        if not (root / 'usr/local/share/cockpit' / name / 'manifest.json').is_file():
            raise ValueError('Install the common Cockpit package first: ' + name)
    return result


def nginx(c):
    host = urlsplit(c['public_origin']).netloc
    profile=brand_profile.load_profile(c['brand'])
    icon_hash=digest(brand_profile.branding_assets(profile)['favicon.ico'])[:12]
    local = f"127.0.0.1:{c['listen_port']}"
    alias = f"listen 127.0.0.1:{c['compatibility_port']};" if c['compatibility_port'] else ''
    return f'''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {{ worker_connections 1024; }}
http {{
 map_hash_bucket_size 128;
 include /etc/nginx/mime.types;
 access_log /dev/stdout;
 client_body_temp_path /tmp/client_temp;
 proxy_temp_path /tmp/proxy_temp;
 map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
 map "$http_host|$http_x_forwarded_proto" $entry {{ default invalid; "{host}|https" public; "{local}|" local; }}
 map $entry $entry_scheme {{ default http; public https; }}
 map $entry $pi_port {{ default {c['pi_local_port']}; public {c['pi_public_port']}; }}
 map "$entry|$http_origin" $origin_allowed {{
  default 0; "public|" 1; "public|{c['public_origin']}" 1;
  "local|" 1; "local|http://{local}" 1;
 }}
 map "$uri|$http_sec_fetch_dest|$http_rsc" $pi_request {{
  default 0; ~^/cockpit/ 0; ~^/woow-pwa/ 0;
  ~^/pi-web(?:/|\\|) 1;
  ~^/(?:api|_next|icons|paseo-web)(?:/|\\|) 1;
  ~^/(?:login|omnigent|paseo/setup|manifest\\.webmanifest|sw\\.js|__woow_cockpit_theme\\.js)\\| 1;
  ~\\|iframe\\| 1; ~\\|1$ 1;
 }}
 server {{
  listen 127.0.0.1:{c['listen_port']}; {alias}
  server_name _;
  if ($entry = invalid) {{ return 403; }}
  if ($origin_allowed = 0) {{ return 403; }}
  client_max_body_size 128m;
  location = /__parallel_auth {{
   internal;
   proxy_pass http://127.0.0.1:{c['cockpit_port']}/cockpit/login;
   proxy_pass_request_body off;
   proxy_set_header Content-Length "";
   proxy_set_header Host $http_host;
   proxy_set_header X-Forwarded-Proto $entry_scheme;
  }}
  location /woow-pwa/ {{
   alias /opt/parallel/public/pwa/assets/;
   types {{ application/manifest+json webmanifest; image/png png; }}
   add_header Cache-Control 'no-store';
  }}
  location = /favicon.ico {{ alias /opt/parallel/public/branding/favicon.ico; add_header Cache-Control 'no-store'; }}
  location = /cockpit/static/favicon.ico {{ alias /opt/parallel/public/branding/favicon.ico; add_header Cache-Control 'no-store'; }}
  location = /favicon.svg {{ alias /opt/parallel/public/branding/assets/logo-symbol-blue.svg; add_header Cache-Control 'no-store'; }}
  location = /apple-touch-icon.png {{ alias /opt/parallel/public/branding/apple-touch-icon.png; add_header Cache-Control 'no-store'; }}
  location = /cockpit/static/apple-touch-icon.png {{ alias /opt/parallel/public/branding/apple-touch-icon.png; add_header Cache-Control 'no-store'; }}
  location = /cockpit/static/brand.json {{ alias /opt/parallel/public/branding/brand.json; default_type application/json; add_header Cache-Control 'no-store'; }}
  location = /cockpit/static/mobile-navigation.js {{ alias /opt/parallel/public/branding/mobile-navigation.js; default_type application/javascript; add_header Cache-Control 'no-store'; }}
  location = /cockpit/static/branding.css {{
   alias /opt/parallel/public/branding/branding.css; default_type text/css; add_header Cache-Control 'no-store';
  }}
  location ^~ /cockpit/static/assets/ {{ alias /opt/parallel/public/branding/assets/; add_header Cache-Control 'no-store'; }}
  location ~ ^/cockpit/(?:@localhost|\\$[a-zA-Z0-9]+)/(woowtech(?:apps|services|backup|preview)|woowpiweb)/(.+)$ {{
   alias /opt/parallel/public/packages/$1/$2;
   auth_request /__parallel_auth;
   add_header Cache-Control 'no-store';
   add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'";
   add_header X-Content-Type-Options nosniff;
  }}
  location / {{
   error_page 418 = @piweb;
   if ($pi_request) {{ return 418; }}
   proxy_pass http://127.0.0.1:{c['cockpit_port']};
   proxy_http_version 1.1;
   proxy_set_header Host $http_host;
   proxy_set_header Origin $http_origin;
   proxy_set_header X-Forwarded-Proto $entry_scheme;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection $connection_upgrade;
   proxy_set_header Accept-Encoding '';
   proxy_read_timeout 3600s;
   sub_filter_once on;
   sub_filter '</head>' '<link rel="icon" type="image/x-icon" href="/favicon.ico?v={icon_hash}"><link rel="manifest" href="/woow-pwa/manifest.webmanifest"><meta name="theme-color" content="{profile['colors']['light']['primary']}"><link rel="apple-touch-icon" href="/apple-touch-icon.png?v={icon_hash}"><script defer src="/woow-pwa/brand-ui.js"></script></head>';
  }}
  location @piweb {{
   rewrite ^/pi-web/?(.*)$ /$1 break;
   proxy_pass http://127.0.0.1:$pi_port;
   proxy_http_version 1.1;
   proxy_set_header Host $http_host;
   proxy_set_header Origin $http_origin;
   proxy_set_header X-Forwarded-Proto $entry_scheme;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection $connection_upgrade;
   proxy_buffering off; proxy_request_buffering off; proxy_read_timeout 3600s;
  }}
 }}
}}
'''


def pi_unit(c, mode):
    directory = f"{BASE}/{c['instance']}/current"
    origin = c['public_origin'] if mode == 'public' else f"http://127.0.0.1:{c['listen_port']}"
    return f'''[Unit]
Description=Cockpit {c['instance']} Pi Web {mode} ingress
After=network-online.target cockpit.socket
[Service]
Type=simple
DynamicUser=yes
Environment=PI_GATEWAY_BIND=127.0.0.1
Environment=PI_GATEWAY_HOST=127.0.0.1
Environment=PI_GATEWAY_PORT={c['pi_'+mode+'_port']}
Environment=PI_GATEWAY_{mode.upper()}_ORIGIN={origin}
Environment=PI_GATEWAY_COCKPIT_PORT={c['cockpit_port']}
Environment=PI_GATEWAY_UPSTREAM_PORT={c['pi_upstream_port']}
Environment=PI_GATEWAY_BRAND_FILE={directory}/public/branding/brand.json
ExecStart={c['node_path']} {directory}/pi-gateway.mjs
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def quadlet(c, release):
    return f'''[Unit]
Description=Cockpit {c['instance']} parallel brand entrance
After=network-online.target
[Container]
Image={c['image']}
ContainerName={c['instance']}-cockpit-pwa
Network=host
Volume={release}/nginx.conf:/etc/nginx/nginx.conf:ro
Volume={release}/public:/opt/parallel/public:ro
NoNewPrivileges=true
[Service]
Restart=on-failure
RestartSec=5
[Install]
WantedBy=default.target
'''


def reference_placeholders(html):
    """Private host captures are intentionally not shipped in reusable releases."""
    def figure(match):
        block=match.group(0)
        if not re.search(r'src="(?:screenshots|layout-images)/',block):return block
        block=re.sub(r'<a\b[^>]*class="shot-link"[^>]*>.*?</a>',
                     '<div class="missing-shot" role="note">尚未建立此設備的畫面紀錄</div>',block,flags=re.S)
        block=re.sub(r'<a\b[^>]*class="open"[^>]*>.*?</a>','',block,flags=re.S)
        block=re.sub(r'<span class="state">.*?</span>','<span class="state">待擷取</span>',block)
        block=re.sub(r'<p class="preview-note">.*?</p>','',block,flags=re.S)
        return block.replace('實機瀏覽器截圖 · 點圖看原尺寸','此設備尚無對應畫面紀錄')
    return re.sub(r'<figure\b[^>]*>.*?</figure>',figure,html,flags=re.S)


def render(c, out, root=Path('/')):
    c = config(c)
    hashes = backend_hashes(root)
    desired, _ = manage.desired_files(root, brand=c['brand'])
    files = {}
    for name, (data, _) in desired.items():
        for prefix, dest in PREFIXES.items():
            if data is not None and name.startswith(prefix+'/'):
                files['public/'+dest+name[len(prefix):]] = data
    for name in ('index.html','layout-review.html'):
        key='public/packages/woowtechpreview/'+name
        files[key]=reference_placeholders(files[key].decode()).encode()
    # Each entrance has its own exact same-origin Pi page; no global package or
    # user's standalone Pi preferences are changed.
    origin = [c['public_origin'], f"http://127.0.0.1:{c['listen_port']}"]
    js = (SOURCE / 'pi-web-integration/package/app.js').read_text()
    start = js.index(' const host=')
    end = js.index(' const systemTheme=')
    js = js[:start] + (' const frame=document.getElementById("pi");\n'
        f' const allowedOrigins={json.dumps(origin)};\n'
        ' const gatewayOrigin=window.location.origin;\n'
        ' if(!allowedOrigins.includes(gatewayOrigin)){frame.hidden=true;document.getElementById("unavailable").hidden=false;return;}\n'
        ' const publicEntry=true;\n') + js[end:]
    for name in ('index.html','style.css'):
        files['public/packages/woowpiweb/'+name] = brand_profile.render_file('pi-web-integration/package/'+name,
            (SOURCE/'pi-web-integration/package'/name).read_bytes(),brand_profile.load_profile(c['brand']))
    files['public/packages/woowpiweb/app.js'] = js.encode()
    manifest = json.loads((SOURCE/'pi-web-integration/package/manifest.json').read_text())
    manifest['content-security-policy'] = "default-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'"
    files['public/packages/woowpiweb/manifest.json'] = (json.dumps(manifest)+'\n').encode()
    files['pi-gateway.mjs'] = (SOURCE/'pi-web-integration/gateway.mjs').read_bytes()
    files['nginx.conf'] = nginx(c).encode()
    for mode in ('public','local'):
        files[f'pi-{mode}.service'] = pi_unit(c, mode).encode()
    for name, data in files.items():
        p = out/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    spec = importlib.util.spec_from_file_location('parallel_pwa', SOURCE/'pwa-gateway/render.py')
    pwa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pwa)
    pwa.render(c['brand'], out/'public/pwa')
    profile=brand_profile.load_profile(c['brand'])
    icon_hash=digest(brand_profile.branding_assets(profile)['favicon.ico'])[:12]
    # Cockpit can reassign its favicon after login; keep this entrance's icon
    # without replacing host titles, account names, service IDs or API data.
    script='''(()=>{'use strict';const expected=ICON;const title=TITLE;let loaded=document.readyState==='complete';
function update(){for(const link of document.querySelectorAll('link[rel="icon"],link[rel="shortcut icon"]')){
if(link.getAttribute('href')!==expected)link.setAttribute('href',expected)}
if(loaded&&document.body?.classList.contains('login-pf')&&document.title!==title)document.title=title}
update();document.addEventListener('DOMContentLoaded',update);window.addEventListener('load',()=>{loaded=true;update()});
new MutationObserver(update).observe(document.head,{subtree:true,childList:true,attributes:true,attributeFilter:['href']});})();'''
    script=script.replace('ICON',json.dumps('/favicon.ico?v='+icon_hash)).replace('TITLE',json.dumps(profile['display_name']))
    (out/'public/pwa/assets/brand-ui.js').write_text(script)
    return hashes
