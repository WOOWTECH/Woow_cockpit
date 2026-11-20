"""Restricted EMQX 5.8.9 operational settings. Never reads files or secret values.

Schema source: apps/emqx_conf/src/emqx_conf_schema.erl at a8319fe.
Node/RPC/cluster are retained at boot and must never be dynamically rewritten.
"""
from .errors import BackupError
from . import ha_odoo

IMMUTABLE_ROOTS = frozenset({'node', 'rpc', 'cluster'})
ROOTS = IMMUTABLE_ROOTS | {'log', 'banned', 'api_key'}
NODE_FIELDS = set('name cookie process_limit max_ports dist_buffer_size max_ets_tables data_dir config_files '
                  'global_gc_interval crash_dump_file crash_dump_seconds crash_dump_bytes dist_net_ticktime '
                  'backtrace_depth applications etc_dir cluster_call db_backend role rpc_module tlog_push_mode '
                  'default_shard_transport shard_transports default_bootstrap_batch_size broker_pool_size '
                  'generic_pool_size channel_cleanup_batch_size'.split())
RPC_FIELDS = set('mode protocol async_batch_size port_discovery server_port client_num connect_timeout certfile '
                 'keyfile cacertfile send_timeout authentication_timeout call_receive_timeout socket_keepalive_idle '
                 'socket_keepalive_interval socket_keepalive_count socket_sndbuf socket_recbuf socket_buffer '
                 'insecure_fallback ciphers tls_versions listen_address ipv6_only'.split())
CLUSTER_FIELDS = set('name discovery_strategy autoclean autoheal proto_dist quic_lb_mode static dns etcd k8s '
                     'prevent_overlapping_partitions'.split())
HANDLER_FIELDS = set('level enable formatter timestamp_format time_offset chars_limit single_line sync_mode_qlen '
                     'drop_mode_qlen flush_qlen overload_kill burst_limit supervisor_reports max_depth with_mfa '
                     'payload_encode'.split())


def refuse():
    raise BackupError('incompatible', 'EMQX 操作設定或檔案路徑超出已核對的支援範圍。')


def fields(value, allowed):
    if not isinstance(value, dict) or set(value) - allowed:
        refuse()


def output_path(path):
    if not isinstance(path, str):
        refuse()
    if path.startswith('${EMQX_LOG_DIR}/'):
        path = '/opt/emqx/log/' + path[len('${EMQX_LOG_DIR}/'):]
    elif path.startswith('log/'):
        path = '/opt/emqx/' + path
    if not path.startswith('/opt/emqx/log/') or ha_odoo._norm(path[1:]) != path[1:]:
        refuse()


def validate(config, mounts):
    if 'node' in config:
        node = config['node']
        fields(node, NODE_FIELDS)
        if node.get('data_dir') not in ('data', '/opt/emqx/data'):
            refuse()
        if node.get('applications', '') not in ('', []):
            refuse()
        if 'etc_dir' in node and node['etc_dir'] not in ('etc', '/opt/emqx/etc'):
            refuse()
        if 'crash_dump_file' in node:
            output_path(node['crash_dump_file'])
        configs = node.get('config_files', [])
        if not isinstance(configs, list):
            refuse()
        for path in configs:
            if path == '/opt/emqx/etc/emqx.conf':
                continue  # unchanged file supplied by the exact target image
            if len([m for m in mounts if m[1] == path and m[2] == 'ro']) != 1:
                refuse()
        if 'cluster_call' in node:
            fields(node['cluster_call'], {'retry_interval', 'max_history', 'cleanup_interval'})
        shards = node.get('shard_transports', {})
        if not isinstance(shards, dict) or any(v not in ('gen_rpc', 'distr') for v in shards.values()):
            refuse()
    if 'rpc' in config:
        rpc = config['rpc']
        fields(rpc, RPC_FIELDS)
        if rpc.get('protocol', 'tcp') not in ('tcp', 'ssl'):
            refuse()
        # Explicit TLS files are handled by the shared reference resolver, including missing-file checks.
        if rpc.get('protocol') == 'ssl' and not all(rpc.get(k) for k in ('certfile', 'keyfile', 'cacertfile')):
            refuse()
    if 'cluster' in config:
        cluster = config['cluster']
        fields(cluster, CLUSTER_FIELDS)
        if cluster.get('discovery_strategy') not in ('manual', 'singleton'):
            refuse()
        if cluster.get('proto_dist', 'inet_tcp') not in ('inet_tcp', 'inet6_tcp'):
            refuse()  # TLS distribution requires separate image/VM-argument validation
        for key, allowed in {
            'static': {'seeds'}, 'dns': {'name', 'record_type'},
            'etcd': {'server', 'prefix', 'node_ttl', 'ssl_options'},
            'k8s': {'apiserver', 'service_name', 'address_type', 'namespace', 'suffix'},
        }.items():
            if key in cluster:
                fields(cluster[key], allowed)
        # These discovery backends are inactive under manual/singleton; never activate/copy their files.
    if 'log' in config:
        log = config['log']
        fields(log, {'console', 'file', 'throttling'})
        if 'throttling' in log:
            fields(log['throttling'], {'time_window', 'msgs'})
        handlers = []
        if 'console' in log:
            fields(log['console'], HANDLER_FIELDS)
            handlers.append(log['console'])
        files = log.get('file', {})
        if not isinstance(files, dict):
            refuse()
        for handler in files.values():
            fields(handler, HANDLER_FIELDS | {'path', 'rotation_count', 'rotation_size'})
            if 'path' in handler:
                output_path(handler['path'])
            elif handler.get('enable', True):
                refuse()
            handlers.append(handler)
        for handler in handlers:
            if 'overload_kill' in handler:
                fields(handler['overload_kill'], {'enable', 'mem_size', 'qlen', 'restart_after'})
            if 'burst_limit' in handler:
                fields(handler['burst_limit'], {'enable', 'max_count', 'window_time'})
    for key in ('banned', 'api_key'):
        if key in config:
            fields(config[key], {'bootstrap_file'})
            if not isinstance(config[key].get('bootstrap_file', ''), str):
                refuse()


# Only empty/disabled target instances are covered. Active connector/plugin/PSK migration
# needs its own dependency review and is intentionally refused.
EMPTY_MAP_ROOTS = frozenset({'actions', 'sources', 'connectors', 'bridges', 'gateway'})
PASSIVE_ROOTS = EMPTY_MAP_ROOTS | {'rewrite', 'topic_metrics', 'auto_subscribe', 'exhook',
                                  'psk_authentication', 'plugins', 'rule_engine'}


def validate_passive(config):
    for key in EMPTY_MAP_ROOTS & config.keys():
        if config[key] != {}:
            refuse()
    for key in ('rewrite', 'topic_metrics'):
        if key in config and config[key] != []:
            refuse()
    for key, field in (('auto_subscribe', 'topics'), ('exhook', 'servers')):
        if key in config:
            fields(config[key], {field})
            if config[key].get(field, []) != []:
                refuse()
    if 'psk_authentication' in config:
        psk = config['psk_authentication']
        fields(psk, {'enable', 'init_file', 'separator', 'chunk_size'})
        if psk.get('enable') is not False or psk.get('init_file', '') != '':
            refuse()
    if 'plugins' in config:
        plugins = config['plugins']
        fields(plugins, {'states', 'install_dir', 'check_interval'})
        if plugins.get('states', []) != [] or plugins.get('install_dir') not in ('plugins', '/opt/emqx/plugins'):
            refuse()
    if 'rule_engine' in config:
        rules = config['rule_engine']
        fields(rules, {'rules', 'ignore_sys_message', 'jq_function_default_timeout', 'jq_implementation_module'})
        if rules.get('rules', {}) != {} or rules.get('jq_implementation_module', 'jq_nif') not in ('jq_nif', 'jq_port'):
            refuse()


MONITOR_ROOTS = frozenset({'limiter', 'prometheus', 'sysmon', 'durable_sessions', 'durable_storage'})


def validate_monitoring(config):
    """5.8.9 local-only profiles; active persistence/exporters require separate review."""
    if 'limiter' in config:
        value = config['limiter']
        types = {'bytes', 'messages', 'connection', 'message_routing', 'internal'}
        fields(value, types | {'max_conn_rate', 'messages_rate', 'bytes_rate'})
        for key in types & value.keys():
            fields(value[key], {'rate', 'burst'})
    if 'prometheus' in config:
        value = config['prometheus']
        collectors = {'vm_dist', 'mnesia', 'vm_statistics', 'vm_system_info', 'vm_memory', 'vm_msacc'}
        legacy = {k + '_collector' for k in collectors}
        fields(value, {'enable_basic_auth', 'push_gateway', 'collectors', 'enable',
                       'push_gateway_server', 'interval', 'headers', 'job_name'} | legacy)
        if value.get('enable', False) is not False:
            refuse()
        if 'push_gateway' in value:
            push = value['push_gateway']
            fields(push, {'enable', 'method', 'url', 'interval', 'headers', 'job_name'})
            if push.get('enable') is not False:
                refuse()
        if 'collectors' in value:
            fields(value['collectors'], collectors)
    if 'sysmon' in config:
        value = config['sysmon']
        fields(value, {'vm', 'os', 'top', 'mnesia_tm_mailbox_size_alarm_threshold',
                       'broker_pool_mailbox_size_alarm_threshold'})
        for key, names in {
            'vm': 'process_check_interval process_high_watermark process_low_watermark long_gc long_schedule large_heap busy_dist_port busy_port',
            'os': 'cpu_check_interval cpu_high_watermark cpu_low_watermark mem_check_interval sysmem_high_watermark procmem_high_watermark',
            'top': 'num_items sample_interval max_procs db_hostname db_port db_username db_password db_name',
        }.items():
            if key in value:
                fields(value[key], set(names.split()))
        if value.get('top', {}).get('db_hostname', '') != '':
            refuse()
    if 'durable_sessions' in config:
        value = config['durable_sessions']
        fields(value, set('enable batch_size idle_poll_interval heartbeat_interval renew_streams_interval session_gc_interval session_gc_batch_size subscription_count_refresh_interval disconnected_session_count_refresh_interval message_retention_period force_persistence'.split()))
        if value.get('enable') is not False or value.get('force_persistence', False) is not False:
            refuse()
    if 'durable_storage' in config:
        # Only the CE builtin local backend while persistent sessions are disabled.
        if config.get('durable_sessions', {}).get('enable') is not False:
            refuse()
        fields(config['durable_storage'], {'messages'})
        if 'messages' not in config['durable_storage']:
            return  # raw config omits the lazy default when durable sessions are disabled
        value = config['durable_storage'].get('messages', {})
        fields(value, {'backend', 'n_shards', 'local_write_buffer', 'layout',
                       'poll_workers_per_shard', 'poll_batch_size'})
        if value.get('backend') != 'builtin_local':
            refuse()
        if 'local_write_buffer' in value:
            fields(value['local_write_buffer'], {'max_items', 'max_bytes', 'flush_interval'})
        if 'layout' in value:
            layout = value['layout']
            fields(layout, {'type', 'bytes_per_topic_level', 'topic_index_bytes', 'serialization_schema'})
            if layout.get('type') != 'wildcard_optimized_v2':
                refuse()
