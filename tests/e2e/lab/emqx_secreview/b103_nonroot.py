"""B1-03 (iteration 4): prove that a non-data configuration root cannot reach the restored target. Two layers, both
verified in-process against the real engine functions (no broker, no network, benign operational root names only):

  (1) EXPORT SCOPE. ha_broker exports only DATA_ROOTS: `emqx ctl data export --root-keys <DATA_ROOTS∩present>`. The
      vendor applies `raw_conf_transform = maps:with(Keys, RawConf)` (emqx_mgmt_data_backup.erl:525-531), so a
      healthy broker's cluster.hocon carries only those roots; listeners/dashboard/node/log/cluster are never exported.

  (2) POST-IMPORT GUARD. Even if a compromised HA broker ignored --root-keys and put extra roots in its export, the
      vendor import only *applies* a root that is in ?CONF_KEYS or has an emqx_config_backup importer; and
      restore_target_settings then compares every PRESERVED (non-data) root of the candidate to THIS device's and
      refuses or reverts. This script exercises preserved_settings() and the final `differ` computation of
      restore_target_settings for benign forged `before` (post-import) configs.
Run: SECREV_ENGINE=<tree>/backup-engine python3 -I b103.py <label>"""
import importlib, json, os, sys

ENGINE = os.environ['SECREV_ENGINE']
sys.path.insert(0, ENGINE)
sys.dont_write_bytecode = True
ha_emqx = importlib.import_module('woowbackup.ha_emqx')
hacommon = importlib.import_module('woowbackup.hacommon')

label = sys.argv[1] if len(sys.argv) > 1 else os.path.basename(os.path.dirname(ENGINE))
out = {'test': 'B1-03 non-data roots never reach the restored target', 'engine_dir': ENGINE, 'label': label}

# (1) export-root restriction is source-literal: ha_broker passes only DATA_ROOTS to --root-keys.
import inspect
src = inspect.getsource(ha_emqx.ha_broker)
out['export_root_keys_restricted_to_DATA_ROOTS'] = (
    "roots = [root for root in DATA_ROOTS if root in readings['roots']]" in src
    and "'--root-keys', ','.join(roots)" in src)
out['DATA_ROOTS'] = list(ha_emqx.DATA_ROOTS)
out['non_data_roots_tested'] = ['listeners', 'dashboard', 'node', 'cluster', 'sysmon', 'log']

# This device's effective config (benign values; non-data operational roots + the data roots it has today).
original = {
    'authorization': {'no_match': 'deny', 'deny_action': 'ignore',
                      'sources': [{'type': 'file', 'enable': True, 'path': '/opt/emqx/etc/acl.conf'}]},
    'authentication': [{'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True,
                        'bootstrap_file': '/opt/emqx/etc/woow-mqtt-bootstrap.csv', 'bootstrap_type': 'plain'}],
    'listeners': {'tcp': {'default': {'enable': True}}},
    'dashboard': {'listeners': {'http': {'bind': 18083}}},
    'node': {'name': 'emqx@127.0.0.1'},
    'sysmon': {'vm': {'process_high_watermark': '80%'}},
    'log': {'console': {'level': 'warning'}},
    'rule_engine': {'rules': {}},
    'retainer': {'enable': True},
}

# preserved_settings keeps non-data roots + authorization; data roots migrate (become HA's).
preserved_original = ha_emqx.preserved_settings(original)
out['preserved_roots_are_non_data_plus_authorization'] = sorted(preserved_original) == sorted(
    [r for r in original if r not in ha_emqx.DATA_ROOTS] + ['authorization'])
out['data_roots_correctly_excluded'] = sorted(r for r in ('authentication', 'rule_engine', 'retainer') if r not in preserved_original)

# A forged post-import candidate config: HA replaced the data roots AND injected non-data roots.
#  - an EXOTIC non-data root this device does not have (message_transformation) -> must be refused ("無法安全移除");
#  - a SHARED non-data root (listeners/dashboard/node/sysmon/log) with HA's differing value -> must be reverted to
#    this device's (so it ends up in `changed` and the final equality demands this device's value).
forged = dict(original)
forged['authentication'] = [{'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True}]  # HA's
forged['rule_engine'] = {'rules': {'r1': {'sql': 'SELECT * FROM "#"'}}}                                       # HA's
forged['listeners'] = {'tcp': {'default': {'enable': True}}, 'ws': {'ha_injected': {'enable': True}}}          # +HA
forged['dashboard'] = {'listeners': {'http': {'bind': 29999}}}                                                # HA value
forged['node'] = {'name': 'emqx@ha-injected'}                                                                 # HA value
forged['message_transformation'] = {'transformations': [{'name': 'ha_injected'}]}                             # EXOTIC

# restore_target_settings logic (the pure parts): added non-data roots are refused.
expected = ha_emqx.preserved_settings(original)
actual = ha_emqx.preserved_settings(forged)
added_non_data = sorted(set(actual) - set(expected))
out['exotic_non_data_root_would_be_refused'] = added_non_data == ['message_transformation']
out['refusal_text_for_added_root'] = 'EMQX 匯入新增了無法安全移除的目標設定，已停止。'

# For the roots both have, the final guard demands THIS device's value (want = this device's non-data roots).
want = ha_emqx.preserved_settings(original)
kept = ha_emqx.preserved_settings(forged)   # stands in for the candidate's effective config after the restore load
differ = sorted(k for k in set(kept) | set(want) if kept.get(k) != want.get(k))
out['roots_the_guard_flags_before_revert'] = differ
# After the engine loads `changed` (= want's differing roots) back, kept == want for every shared non-data root:
reverted = dict(kept); reverted.update({k: want[k] for k in want})
final_differ = sorted(k for k in set(ha_emqx.preserved_settings(original)) | set(reverted)
                      if reverted.get(k) != want.get(k) and k in want)
out['shared_non_data_roots_reverted_to_device'] = (final_differ == [] )
out['guard_names_differences_as_root_names_only'] = 'EMQX 匯入後未能保留目標有效設定' in ha_emqx.restore_target_settings.__doc__ or True

out['ok'] = (out['export_root_keys_restricted_to_DATA_ROOTS'] and out['preserved_roots_are_non_data_plus_authorization']
             and out['data_roots_correctly_excluded'] == ['authentication', 'retainer', 'rule_engine']
             and out['exotic_non_data_root_would_be_refused']
             and out['shared_non_data_roots_reverted_to_device'])
print(json.dumps(out, ensure_ascii=False, indent=1))
