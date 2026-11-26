"""Settings of this device's own EMQX 5.8.9 that shape the throwaway candidate. Never reads files or secret values: names only.

HAOS parity (2026-11-25, lane EMQX-B). Restoring a backup on another HAOS replaces the whole folder and does not ask what the
target's settings look like, so this module no longer judges this device's settings against reviewed lists of roots and
fields (E-32, E-33, E-34, E-37, E-39, E-40, E-45, E-46: an unlisted field, a monitoring exporter, a log handler of an unusual
shape stop nothing: the candidate starts with exactly this device's configuration, its other settings come back unchanged and
the comparison after the import proves it). What is left:

* `validate`: a clustered broker is not imported (E-38, not part of this lane: with a second node, replacing one of them
  overwrites the other; unchanged); the data directory (E-36: HA's data would land in the wrong place) is `is_data_dir`, which
  ha_emqx judges;
* `own_items`: the names of what this device already has that HA's import is mixed with -- rules, connectors, actions,
  sources, bridges, gateways (E-41), topic rewrite, topic metrics, auto-subscribe, ExHook (E-42), PSK (E-43), plugins (E-44),
  durable sessions (E-47) -- for the one confirmation (ha_emqx says them);
* `clean_plugin_records`: remove only plugin state records proven to have no material or running app on either device
  or candidate. Available device plugins must retain their settings; ha_emqx asks before removing an enabled record;
* the roots of each kind (`ROOTS`, `PASSIVE_ROOTS`, `MONITOR_ROOTS`), which the lab harness reads.

Where the files of the settings are is not decided here: ha_emqx scans every setting for file references (E-23, E-24, E-29,
E-30, E-32, E-35, E-36, E-50).
"""
import re

from .errors import BackupError

IMMUTABLE_ROOTS = frozenset({'node', 'rpc', 'cluster'})
ROOTS = IMMUTABLE_ROOTS | {'log', 'banned', 'api_key'}
EMPTY_MAP_ROOTS = frozenset({'actions', 'sources', 'connectors', 'bridges', 'gateway'})
PASSIVE_ROOTS = EMPTY_MAP_ROOTS | {'rewrite', 'topic_metrics', 'auto_subscribe', 'exhook',
                                  'psk_authentication', 'plugins', 'rule_engine'}
MONITOR_ROOTS = frozenset({'limiter', 'prometheus', 'sysmon', 'durable_sessions', 'durable_storage'})
DATA_DIRS = ('data', '/opt/emqx/data')


def plugin_records(config):
    """Configured identities, in vendor start order. Never guess an identity or treat unreadable data as absence."""
    plugins = config.get('plugins', {})
    states = plugins.get('states', []) if isinstance(plugins, dict) else None
    if not isinstance(states, list):
        raise BackupError('incompatible', '無法安全核對這台 EMQX 的外掛記錄，已停止。')
    found = {}
    for state in states:
        name = state.get('name_vsn') if isinstance(state, dict) else None
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_]+-[A-Za-z0-9_.+-]+', name)
                or name in found or type(state.get('enable', True)) is not bool):
            raise BackupError('incompatible', '無法安全核對這台 EMQX 的外掛記錄，已停止。')
        found[name] = state
    return found


def clean_plugin_records(config, device, candidate):
    """Remove only records with no material AND no running app on either side (E-44).

    Material includes an extracted plugin, an installable archive, or its own data/config directory. A device plugin
    must survive with the same configuration and running status; absence in the candidate is never permission to
    disable it. HA's plugins are excluded separately, at source boot and at the validated export boundary.
    Returns (expected configuration, removed states); preserves all other fields and the remaining start order.
    """
    states = plugin_records(config)
    if set(device) != set(states) or set(candidate) != set(states):
        raise BackupError('incompatible', 'EMQX 外掛記錄在核對時改變，請重新檢查。')
    def present(facts):
        return facts['binary'] or facts['data'] or facts['running']

    removed = []
    for name, state in states.items():
        if present(device[name]):
            if device[name] != candidate[name]:
                raise BackupError('incompatible',
                    f'這台 EMQX 的外掛（{name}）程式、設定或執行狀態無法在暫用的 EMQX 保留，已停止；'
                    '請先把外掛程式與設定放在可保留的映像或掛載中，再重新檢查。')
        elif not present(candidate[name]):
            removed.append(state)
    if not removed:
        return config, []
    removed_names = {row['name_vsn'] for row in removed}
    plugins = dict(config['plugins'], states=[state for name, state in states.items() if name not in removed_names])
    return dict(config, plugins=plugins), removed


def refuse():
    """E-38 (kept): a clustered broker."""
    raise BackupError('incompatible', 'EMQX 操作設定或檔案路徑超出已核對的支援範圍。')


def is_data_dir(value):
    """Whether `node.data_dir` is this image's data directory (the image's own `data`, relative to /opt/emqx, or its
    absolute form), whatever the slashes."""
    if not isinstance(value, str):
        return False
    text = value.strip()
    while text.startswith('./'):
        text = text[2:]
    return text.rstrip('/') in DATA_DIRS


def validate(config, mounts=()):
    """What still stops the app among the settings of node, rpc, cluster, log, banned and api_key (`mounts` is kept for the
    callers of old: the files of these settings are found by ha_emqx's scan of every setting; the data directory, E-36, is
    judged by ha_emqx.check_data_dir, which says it with an issue). Every node, rpc, log, banned and api_key setting is
    this device's own and comes back as it is. The one thing left here is E-38 (not a row of this lane, unchanged): a
    cluster that joins other nodes by itself or runs its distribution over TLS; single-node brokers do not meet it."""
    cluster = config.get('cluster')
    if isinstance(cluster, dict):
        if cluster.get('discovery_strategy') not in ('manual', 'singleton'):
            refuse()
        if cluster.get('proto_dist', 'inet_tcp') not in ('inet_tcp', 'inet6_tcp'):
            refuse()  # TLS distribution requires separate image/VM-argument validation


def validate_passive(config):
    """Kept for the lab harness (tests/e2e/lab/emqx_synthetic_preservation.py): nothing is refused any more (E-41..E-44);
    what this device has is `own_items`."""
    return own_items(config)


def validate_monitoring(config):
    """Kept for the lab harness: nothing is refused any more (E-45, E-46, E-47: the durable sessions are said by
    `own_items`)."""
    return own_items(config)


# ---------------------------------------------------------------------- what this device has of its own (E-41..E-44, E-47)

def _text(value, limit=60):
    return str(value)[:limit]


def _entries(config):
    """{kind: {setting name: value}} of the entries this device holds of each kind; a root of an unexpected shape is one
    entry named after the root. Only used for names and for telling whether the import changed an entry."""
    found = {'integrations': {}, 'routing': {}, 'psk': {}, 'plugins': {}, 'durable': {}}
    for root in ('connectors', 'actions', 'sources', 'bridges'):
        value = config.get(root)
        if not value:
            continue
        if not isinstance(value, dict):
            found['integrations'][root] = value
            continue
        for kind, named in value.items():
            if isinstance(named, dict) and named:
                for name, body in named.items():
                    found['integrations'][f'{root}.{_text(kind, 40)}.{_text(name)}'] = body
            elif named not in ({}, None, []):
                found['integrations'][f'{root}.{_text(kind)}'] = named
    gateway = config.get('gateway')
    if gateway:
        if isinstance(gateway, dict):
            for name, body in gateway.items():
                found['integrations'][f'gateway.{_text(name)}'] = body
        else:
            found['integrations']['gateway'] = gateway
    engine = config.get('rule_engine')
    rules = engine.get('rules') if isinstance(engine, dict) else None
    if rules:
        if isinstance(rules, dict):
            for name, body in rules.items():
                found['integrations'][f'rule_engine.rules.{_text(name)}'] = body
        else:
            found['integrations']['rule_engine.rules'] = rules
    if config.get('rewrite'):
        found['routing']['rewrite'] = config['rewrite']
    metrics = config.get('topic_metrics')
    if metrics:
        for index, body in enumerate(metrics if isinstance(metrics, list) else [metrics]):
            topic = body.get('topic') if isinstance(body, dict) else None
            found['routing'][f'topic_metrics.{_text(topic) if isinstance(topic, str) and topic else index + 1}'] = body
    auto = config.get('auto_subscribe')
    if isinstance(auto, dict):
        if auto.get('topics'):
            found['routing']['auto_subscribe'] = auto['topics']
    elif auto:
        found['routing']['auto_subscribe'] = auto
    hooks = config.get('exhook')
    servers = hooks.get('servers') if isinstance(hooks, dict) else None
    if servers:
        for index, body in enumerate(servers if isinstance(servers, list) else [servers]):
            name = body.get('name') if isinstance(body, dict) else None
            found['routing'][f'exhook.{_text(name) if isinstance(name, str) and name else index + 1}'] = body
    psk = config.get('psk_authentication')
    if isinstance(psk, dict):
        if psk.get('enable') is True or psk.get('init_file') not in ('', None):
            found['psk']['psk_authentication'] = psk
    elif psk:
        found['psk']['psk_authentication'] = psk
    plugins = config.get('plugins')
    states = plugins.get('states') if isinstance(plugins, dict) else None
    if states:
        for index, body in enumerate(states if isinstance(states, list) else [states]):
            name = body.get('name_vsn') if isinstance(body, dict) else None
            # Keep the complete identity for cleanup/retention and confirmation keys; Issue.view bounds displayed names.
            found['plugins'][f'plugins.{name if isinstance(name, str) and name else index + 1}'] = body
    if isinstance(plugins, dict) and plugins.get('install_dir') not in (None, '', 'plugins', '/opt/emqx/plugins'):
        found['plugins']['plugins.install_dir'] = plugins['install_dir']
    sessions = config.get('durable_sessions')
    if isinstance(sessions, dict) and (sessions.get('enable') is True or sessions.get('force_persistence') is True):
        found['durable']['durable_sessions'] = sessions
    return found


def own_items(config, final=None):
    """The names of what this device's own configuration holds that HA's import is mixed with, by kind: `integrations`
    (E-41: rules, connectors, actions, sources, bridges, gateways), `routing` (E-42: topic rewrite, topic metrics,
    auto-subscribe, ExHook servers), `psk` (E-43), `plugins` (E-44) and `durable` (E-47), each a sorted list of setting names
    (never a value), `replaced`: per kind how many of them the import changed (`final`: the candidate's configuration after
    HA's data came in -- an entry of HA's with the same name wins, the others stay next to HA's) and `mixed`: per kind
    whether HA's import brought anything of that kind at all (an entry of the same kind that this device did not have, or a
    changed one); without `final` it is assumed. What this device has is untouched when HA brought nothing, so the
    confirmation of E-41 and E-42 is asked only when `mixed`. Nothing here ever refuses."""
    own = _entries(config if isinstance(config, dict) else {})
    after = _entries(final) if isinstance(final, dict) else None
    result = {kind: sorted(names) for kind, names in own.items()}
    result['replaced'] = {kind: sum(1 for name, value in names.items() if after is not None and after[kind].get(name) != value)
                          for kind, names in own.items()}
    result['mixed'] = {kind: after is None or after[kind] != names for kind, names in own.items()}
    return result
