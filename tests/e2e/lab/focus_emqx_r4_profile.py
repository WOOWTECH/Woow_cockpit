"""One immutable synthetic package profile shared by producer and receiver. No process or device calls."""
import hashlib
import json
from pathlib import Path
import focus_emqx_r4_fixtures as fx

PROFILE = 'emqx-r4-package-v1'
PACKAGE_COMMIT = 'ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de'
PACKAGE_FILES = {
    "config/acl.conf": "5690c6143ea84510c977e8736915c44532f99fca5efffe7444d31020a1f8f70f",
    "config/base.hocon": "f65f2a2c00037ad1a60c6fe4bdf77017c7d99cff430e8ff82cbbb56c38835a32",
    "config/entrance.conf": "700855339d9afa8dffa9487bf394ea4dc232853d815e94173c4be2eac9501289",
    "quadlet/emqx-data.volume": "ead9e52d7a5cc0d4d614b3169aa7bdaaa7b7b735c2ac2c8864a98599845c9e65",
    "quadlet/emqx-entrance.container": "820cdfbca0d23c1d25c7bffb34825f70b76b63e9f65ed6a556a462d94cb007b9",
    "quadlet/emqx-log.volume": "6f11c4a3514101c6dacfd242a27a1a1b0b00070efd5a6849ee4a6fea3cd035e9",
    "quadlet/emqx.container": "c1a1c64c84e07bf5eb05d6f0abaf50c0747150aec5fcc548e2edc0704d894c3f",
    "quadlet/emqx.network": "11dad0f61f35c1d2740b146416058f95c4088a14bcfd863af5974474f0d6d6f4",
    "scripts/common.sh": "71dbfd2359ac992d3ce10a3e75b9f87f7f9cbce65f229b959f902747290458af",
    "scripts/lib/quadlet-lib.sh": "1d50ecbbf77ed9da40fad5644d1731901003379a8eca6b0e3e87f0ab0b847018",
    "tests/smoke.sh": "a14d0f562875027db0c2659f6bf9ba09412fe49aab6e1bf9b0ca50588c7a8e2b"
}

ENV = {
    'EMQX_NODE__NAME': fx.NODE, 'ERL_AFLAGS': '+S 1:1', 'EMQX_LOG__CONSOLE__LEVEL': 'error',
    'EMQX_DASHBOARD__DEFAULT_USERNAME': 'admin', 'EMQX_DASHBOARD__DEFAULT_PASSWORD': 'r4-owned-target-admin',
    'EMQX_NODE__COOKIE': 'r4-owned-package-cookie',
    'EMQX_DASHBOARD__LISTENERS__HTTP__BIND': '"0.0.0.0:18093"',
    'EMQX_LISTENERS__WS__ENTRANCE__ENABLE': 'true', 'EMQX_LISTENERS__WS__ENTRANCE__BIND': '"127.0.0.1:8093"',
    'EMQX_LISTENERS__WS__ENTRANCE__WEBSOCKET__PROXY_ADDRESS_HEADER': '"x-forwarded-for"',
    'EMQX_LISTENERS__WS__ENTRANCE__WEBSOCKET__PROXY_PORT_HEADER': '"x-forwarded-port"',
    'EMQX_LISTENERS__WS__DEFAULT__WEBSOCKET__PROXY_ADDRESS_HEADER': '""',
    'EMQX_LISTENERS__WS__DEFAULT__WEBSOCKET__PROXY_PORT_HEADER': '""',
    'EMQX_LISTENERS__TCP__NGROK__ENABLE': 'true', 'EMQX_LISTENERS__TCP__NGROK__BIND': '"127.0.0.1:1884"',
    'EMQX_LISTENERS__TCP__NGROK__PROXY_PROTOCOL': 'true',
}


def sha(data): return hashlib.sha256(data).hexdigest()


def secret_values():
    return {'woow-emqx-dashboard-password': ENV['EMQX_DASHBOARD__DEFAULT_PASSWORD'].encode(),
            'woow-emqx-node-cookie': ENV['EMQX_NODE__COOKIE'].encode(),
            'woow-emqx-mqtt-password': b'r4-owned-target-password',
            'woow-emqx-mqtt-bootstrap': fx.files()['target.csv']}


def env_file():
    return ('EMQX_LOG__CONSOLE__LEVEL=error\nWOOW_EMQX_BIND=127.0.0.1\nWOOW_EMQX_MQTT_USER=r4_target\n'
            'WOOW_EMQX_NGROK=0\nWOOW_EMQX_NGROK_REMOTE_ADDR=\n' + ''.join(
            'WOOW_EMQX_PORT_'+key+'='+str(port)+'\n' for key,port in
            [('MQTT',1883),('MQTTS',8883),('WS',8083),('WSS',8084),('DASHBOARD',18083)]))


def material_hashes():
    return {'/opt/emqx/etc/base.hocon': PACKAGE_FILES['config/base.hocon'],
            '/opt/emqx/etc/acl.conf': PACKAGE_FILES['config/acl.conf'],
            '/opt/emqx/etc/woow-mqtt-bootstrap.csv': sha(fx.files()['target.csv']),
            **{'/fixture/'+name:sha(body) for name,body in fx.files().items()}}


def receipt():
    definition={'profile':PROFILE,'package_commit':PACKAGE_COMMIT,'package_files':dict(PACKAGE_FILES),
        'effective_environment':dict(ENV),'owner_env_sha256':sha(env_file().encode()),
        'mount_sha256':material_hashes(),'bootstrap_metadata':'400:1000:1000',
        'secret_sha256':{name:sha(value) for name,value in secret_values().items()},
        'initial_target_cluster_config':{},'node':fx.NODE,'schedulers':'1:1'}
    encoded=json.dumps(definition,sort_keys=True,separators=(',',':')).encode()
    return {'profile':PROFILE,'sha256':sha(encoded),'definition':definition}


def package_bytes(directory):
    root=Path(directory);result={}
    for name,expected in PACKAGE_FILES.items():
        path=root/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size>1024**2:
            raise ValueError('bounded_reviewed_package_file_required')
        data=path.read_bytes()
        if sha(data)!=expected:raise ValueError('package_blob_hash_mismatch')
        result[name]=data
    return result
