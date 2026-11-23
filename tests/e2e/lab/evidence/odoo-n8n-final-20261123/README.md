# Odoo／n8n HA 匯入：2026-11-23 實測（dev-c，odoo-n8n 小組）

全部在實驗室設備 woowbk-dev-c（network none、沒有對外連接埠）跑，引擎是 feat/ha-import-batch1 b2f63ce 的
backup-engine（39 個 .py 檔與設備內安裝的副本逐檔相同，彙總 sha256 `7bf56d30…`；helper `539c32a6…`）。
每次嘗試一份 JSON（結束碼、只有固定的 PASS/FAIL 行、秒數、stdout sha256、來源 commit）；
失敗的嘗試照樣保留。`commercial_acceptance` 一律是 `not-complete`：這是一條小組在實驗室的實測，不等於商業驗收。
私有證據（含密碼雜湊以外的細節、日誌）在 `~/.woowbk-lab/evidence/odoo-n8n-final-*`，不提交。

## 結論

| 項目 | 結果 | 證據 |
| --- | --- | --- |
| n8n 社群節點探測逾時的根因 | **探測的問題，不是還原的問題。** `GET /rest/community-packages` 在有安裝社群套件時會先等 `npm outdated --json`（n8n 2.43.6 `community-packages.lifecycle.service.js:62-90`；`npm-utils.js:118` 呼叫 npm 沒有逾時）。實測：請求 87.5 秒才回 200，`npm outdated` 在 n8n 容器裡從第 4.1 秒跑到第 86.1 秒（24 次取樣中 23 次看到）；舊探測 60 秒就放棄，所以 11-21 是 TimeoutError。同一個工作階段改用本機探測（資料庫列＋套件檔案＋執行中的節點型別）0.5 秒通過，節點 `n8n-nodes-globals 1.1.0` 已載入。對照組 x86（沒有社群套件）：同一個 API 0.1 秒回 `[]`，沒有 npm 程序（`:63-65`）。 | `arm-full-real.json` 的 `n8n_diagnosis`；`x86-full-real.json` |
| Odoo 4 張表的差異 | **全部是預期的執行期紀錄與匯入本身的設定，匯入程式不用改。** ARM（與 11-21 同一份備份）：201 張表完全相同；差異 35 列逐列對上規則：`ir_config_parameter` 3 列（`web.base.url` 改成這台的值、`web.base.url.freeze` 刪除、`woow_paas_platform.upgrade_done` 新增＝匯入的 `settings_sql`）、`ir_cron` 13 個排程只動 `lastcall`／`nextcall`（還原後 2 分鐘內執行）、`ir_cron_progress` 新增 13 列（每個執行的排程一列）、`bus_bus` 6 列（2026-11-19 建立、超過 24 小時，被 `base.autovacuum_job` 清掉）。來源擷取與 RPi5 上量的指紋 205／205 張表完全相同。 | `capture-arm-real.json`、`arm-full-real.json` 的 `armcompare` |
| x86 額外發現 | x86 備份（11-18）滿 5 天：Odoo 的每日 `auth_signup` 排程替「5 天前建立、沒登入過」的使用者寄提醒（新增 1 封排隊信＋1 則訊息）；備份裡原本排隊的 1 封信被每小時的寄信排程試寄，實驗室沒有網路所以變成 `exception`。兩者都是 Odoo 自己的排程（`res_users.py:248-276`、`mail_mail.py:218-266`、`:637-649`）。第 4 次擷取（規則在跑之前就定好）39 列全部有規則、其餘表完全相同。 | `capture-x86-attempt1..4` |
| ARM 完整實測 | **133／133 通過**（基準、上傳、金鑰、檢查×3、轉換、還原、逐列比對、驗證、n8n 診斷、整組重新啟動、db2、測試模式、下載版、ARM 專用程式、非正常停止、清理、外洩掃描、回到基準）。 | `arm-full-real.json` |
| x86 完整實測 | **94／94 通過**（同上，沒有 ARM 專用情境）。 | `x86-full-real.json` |
| x86 整個資料庫比對（經真正的 helper 作業匯入） | **24／24 通過**：還原後 205 張表與同一份備份的來源擷取相比，199 張完全相同，6 張表的 39 列逐列對上規則（同上）。 | `x86-capcompare-real.json` |
| x86 失敗與回復情境 | **40／40 通過**（`x86-fix-real.json`：中途砍掉、取消、空間不足兩種、C-19 設定沿用、還原失敗自動回復到還原前的資料）。`pull`（從 Docker Hub 下載 PostgreSQL 16）在沒有網路的 dev-c 不能跑，沒有列入。 | `x86-fix-real.json` |

## 逐列規則（`tests/e2e/lab/odoo_explain.py`）

沒有任何一張表被整張豁免：每一列的新增、刪除、修改都要對上一條規則，否則失敗；結構變更、其他欄位、其他表、
規則以外的鍵都算失敗。規則與原始碼位置（dev-c 映像內 Odoo 18.0-20260926）：

* import-settings：引擎 `ha_odoo.py settings_sql()`（網址、freeze、升級標記換成這台的值）。
* cron-schedule：`ir_cron.py:457-509`、`:511-540`（只改 `failure_count`、`first_failure_date`、`nextcall`、`lastcall`），還要在 Odoo 日誌看到該排程「starting」。
* cron-progress：`ir_cron.py:391-455`、`:714-732`（每次執行一列）。progress-gc：`:782-784`（一週以上才刪）。
* bus-gc：`bus.py:95-104`（保留 24 小時，`bus.py:25`）由 `ir_autovacuum.py:25-42` 執行；bus-runtime：`bus.py:106-140`。
* signup-reminder：`auth_signup/models/res_users.py:248-276`、`mail_template.py:620-660`、`mail_mail.py:30`、`:47`、`:65-71`。
* mail-queue-failed：`mail_mail.py:218-266`、`:637-649`（只在連不到寄信伺服器時；真的寄出或刪除仍然算未解釋）。

## 給負責人的觀察（不是缺陷）

正式匯入（非測試模式）後，Odoo 會照常跑自己的排程：備份裡排隊的信、以及「5 天前建立、沒登入過」使用者的提醒信，
在一台連得到寄信伺服器的主機上會真的寄出。測試模式會停用寄信（已實測）。要不要在匯入頁面提醒，由負責人決定。
