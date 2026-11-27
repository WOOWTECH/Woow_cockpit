# E-44 coordinator integration snippet

Assigned source/test changes are local to this worker. Shared guide, contract and registry are intentionally left to the coordinator.

## docs/backup.md and docs/backup/CONTRACT.md

Replace the old statement that all plugins live in the container and all records stay with this policy:

- HA 的外掛程式永不搬入。來源暫用 EMQX 強制空白 plugins.states 與映像的 install_dir；匯出不含 plugins 根，匯入前檢查仍拒絕該根及任何外掛檔案。
- 這台映像或掛載裡可用的外掛與原設定、順序、install_dir 保留。只在裝置與候選兩邊均證明沒有程式目錄、安裝包、外掛資料目錄及執行中的應用時移除對應記錄。
- 移除啟用記錄（含省略 enable、原廠預設 true）列在唯一一次確認；已停用且無程式或資料的記錄移除列為提醒。新增名稱或從停用改啟用需要新的確認。
- 裝置有外掛程式或設定，而候選無法保留同樣存在狀態、config.hocon 雜湊及執行狀態時，僅停止 EMQX 匯入。先把裝置外掛與設定放在可保留的映像或掛載，或另行準備完整裝置外掛搬移方案；不可把缺失當作停用同意。
- 載入預期的 plugins 根後仍逐根比較全部操作設定；外掛的核對在匯入後再讀一次。vendor export、HA-admin 表及還原核對照舊。

Engine messages (use these verbatim in both documents):

這台 EMQX 的外掛設定（共 N 項，列在下面）會保留；已核對外掛程式、設定及執行狀態可在暫用的 EMQX 保留。HA 備份的外掛程式及啟用記錄不會搬入，需要 HA 的外掛時請另外安裝。

這台 EMQX 有 N 個啟用中的外掛記錄（列在下面），但這台與暫用的 EMQX 都找不到其程式、安裝包、外掛資料或執行中的程式。匯入會移除這些啟用記錄，以後補上程式也不會自動啟用；需要時請重新安裝並啟用。匯入前的自動備份保留原記錄。

這台 EMQX 有 N 個已停用、且這台與暫用的 EMQX 都沒有程式或資料的外掛記錄（列在下面），匯入會移除這些記錄。

## Registry row E-44

Replace references to `OwnLinesTests.test_plugins_are_a_notice_and_nothing_is_cleared` with:

- `tests/backup/test_ha_emqx_operational.py::PluginInventoryTests`
- `tests/backup/test_ha_emqx_operational.py::OwnLinesTests.test_available_device_plugins_keep_configuration_and_records`
- `tests/backup/test_ha_emqx_operational.py::OwnLinesTests.test_enabled_missing_records_need_confirmation_and_new_names_need_it_again`
- `tests/backup/test_ha_emqx_operational.py::OwnLinesTests.test_disabled_missing_records_are_cleaned_with_a_notice`
- `tests/backup/test_ha_emqx_operational.py::OwnLinesTests.test_device_plugin_material_or_configuration_lost_by_candidate_stops_the_import`
- `tests/backup/test_ha_emqx_operational.py::OwnLinesTests.test_a_failed_record_cleanup_is_not_hidden_by_the_configuration_comparison`

Issues: `emqx.device-plugins: notice`, `emqx.plugin-records-remove: confirm`, `emqx.plugin-records-unused: notice`.

The coordinator has already integrated the initial policy/messages/test references. Add the startup-override guard `d787b6a1` and native evidence from this lane before closing E-44 implementation: exact-image attempt 3 at source `a82a086f` passed 33/33 checks (`runtime-attempt3-pass.json`), including genuine available plugin/config/order retained, enabled-missing exact confirmation, no-ack refusal, ack cleanup/restart persistence, real vendor import/count/config/admin postchecks and negative admin validation. `runtime-cleanup.json` records zero owned resources, private payload removal and mutation-lock release. See `runtime-plan.md` for exact command/budget, retained failures and measurement limits. The generated delta supplements existing real EMQX full-flow evidence; it does not complete all R4 or ten-service acceptance. No own shared-row edits were made.

### Additional startup-override refusal

When high-priority startup configuration defines plugins.states, or EMQX_PLUGINS / EMQX_PLUGINS__STATES is set, a missing record cannot safely be cleared persistently. Stop this EMQX import and ask the customer to remove that specific override before retrying. No environment value is shown. The new guarded operational test is `OwnLinesTests.test_startup_overrides_that_would_resurrect_a_record_stop_cleanup`.
