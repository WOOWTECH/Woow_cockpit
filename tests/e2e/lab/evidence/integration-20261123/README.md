# HA 匯入第一次整合與 dev-c 真實重驗：2026-11-23（integration-1 小組）

分支 `integration/ha-import-batch1-20261123`（只在本機，沒有推送、沒有 PR），起點 `feat/ha-import-batch1` `b2f63ce`。
每次真實嘗試一份 JSON（結束碼、只有固定的 PASS/FAIL 行、秒數、stdout sha256、來源 commit），失敗的嘗試照樣保留
（這次沒有失敗的嘗試）。`commercial_acceptance` 一律是 `not-complete`：這是一條小組在實驗室的重驗，不等於商業驗收。
私有證據（日誌、作業紀錄）在 `~/.woowbk-lab/evidence/integration-*-20261123/`（0700），不提交。

## 合併了什麼（全部 `--no-ff`，依序）

| 合併 commit | 來源分支（tip） | 內容 |
| --- | --- | --- |
| `7790cf8` | `fix/hasqlite-netns-fail-closed-20261123`（`10fe446`） | hasqlite 與 ha_n8n 的 SQLite 子程序：切不斷網路就停（NO_NETNS=3 → job-failed，不再退回用主機網路讀）；Python < 3.12 改用 libc `unshare`；Hermes 審查證據 |
| `a8b7a04` | `test/large-archive-final-20261123`（`e415fc4`） | >8GiB 有界探測、真正的 job-cancel CLI 取消、不可壓縮外層封存證據 |
| `1bd5dcc` | `test/odoo-n8n-final-20261123`（`e2515f8`） | Odoo 逐列解釋規則、n8n 診斷、ARM／x86 真實證據 |
| `110b881` | `test/services-a-final-20261123`（`5ab3249`） | Headscale／Omnigent 真實 HA 備份鏈與證據 |

**合併衝突：沒有。** 四條分支一共改 80 個檔案，沒有任何一個檔案被兩條分支同時修改；合併後逐一確認每條分支自己改的
檔案在整合分支與該分支 tip 位元組完全相同（12／25／22／21 個檔案，差異 0），所以沒有內容被丟掉或改寫。
沒有合併：`test/arm54-final-20261123`（仍在進行，早期 commit 含測試密碼字面值，最後以 squash 合併）、R-EMQX 線（仍在跑）。
`tests/e2e/lab/evidence/cross-device-focus-20261122/status.json` 刻意沒有改：arm54 分支也改這個檔案（+48 行），留給最後的
squash 合併，避免多一個衝突。arm54 分支的 `ha_hermes.py`、`ha_n8n.py`、`hasqlite.py` 與這裡完全相同。

整合後新增（都在合併之後、真實測試之前提交）：`9487e17` 單元測試證據；`ba618ba` `sandbox_netns_sampler.py`
（唯讀觀察 SQLite 沙箱子程序的網路命名空間，4 個離線測試）。之後的 commit 只加證據檔。

## 單元測試（`unit-tests.json`，測試 commit `110b881`）

全部在主機上跑，程序內守衛禁止執行 podman／labpodman／ssh／sudo／systemctl／runuser（主機的 `/usr/bin/podman` 是正式環境的
rootless 儲存區，從來不碰）。HA 金鑰在程序內用 shlex 從 `ha-import-creds.env` 讀進環境變數，沒有印出，日誌已遮蔽。

| 套件 | 結果 |
| --- | --- |
| `tests/backup`（全部，開啟真實 batch-1 HA 備份） | 1397 個：1374 通過、1 略過、22 未通過，其中 **17 個是既有的公開防護**（`test_ha_emqx` 10 個＝PRESERVATION_BLOCKER、`test_ha_omnigent` 7 個＝SECURITY_BLOCKER；在 `b2f63ce` 重跑，同樣 24 個測試、同樣 14 失敗＋3 錯誤、同樣的測試名稱），**5 個是我的守衛誤擋**（`test_litellm_lab_runner` 用暫存的假程式，參數裡有 podman 這個字；只看執行檔的守衛重跑 6／6 通過、0 次被擋）。`test_ha_b1_real` 5／5 通過（真實 ARM＋x86 batch-1 備份）。 |
| 略過的那 1 個 | `test_ha_backup.RealBackupTests`（要 `WOOWBK_HA_FIXTURES`）：用 20261118 的真實 HA 備份（加密、未加密、加密未壓縮）重跑 1／1 通過。 |
| `tests/e2e/lab`（30 個模組，全部是模擬／離線） | 259／259 通過，0 次被擋。 |

沒有改任何測試、斷言或防護；EMQX PRESERVATION_BLOCKER 與 Omnigent SECURITY_BLOCKER 照舊啟用。

## dev-c 真實重驗（整合後的引擎）

部署：11:42 用 `tests/e2e/lab/deploy-src.sh c --src /tmp/ha-import-integration-20261123 --no-demo-catalog`
（與 odoo-n8n 小組相同的方法）安裝 `ba618ba` 的工作樹；改到 `ha_hermes.py`、`ha_n8n.py`、`hasqlite.py` 與 `installed.json`。
裝好的 39 個 .py 與樹逐檔相同，helper `539c32a6…` 沒變；彙總 `2fcd4a60…`
（`find woowbackup -name '*.py' | LC_ALL=C sort | xargs sha256sum | sha256sum`）。驅動程式、真實備份與參數都與 odoo-n8n 小組相同。

| 項目 | 結果 | 證據 |
| --- | --- | --- |
| ARM 完整實測（RPi5 真實 HA 備份 20261119-arm，add-on 0.4.13） | **133／133 通過**，2833 秒：基準、上傳、金鑰、檢查×3、轉換、還原、逐列比對（205 張表 201 張完全相同，35 列全部對上規則：import-settings 3、cron-schedule 13、cron-progress 13、bus-gc 6）、驗證、n8n 診斷、整組重新啟動、db2、測試模式、下載版、ARM 專用程式、非正常停止、清理、外洩掃描（683 個檔案 0 命中）、回到基準。 | `arm-full-real.json` |
| x86 完整實測（x86 真實 HA 備份 20261118，add-on 0.4.12） | **94／94 通過**，2065 秒（同上，沒有 ARM 專用情境；外洩掃描 689 個檔案 0 命中）。 | `x86-full-real.json` |
| x86 失敗與回復情境 | **40／40 通過**，699 秒：中途砍掉、取消、空間不足兩種、C-19 設定沿用、還原失敗自動回復到還原前的資料。 | `x86-fix-real.json` |
| x86 整個資料庫比對（經真正的 helper 作業匯入） | **24／24 通過**，928 秒：205 張表與同一份備份的來源擷取相比，199 張完全相同，6 張表 39 列逐列對上規則（含 signup-reminder 2、mail-queue-failed 1）。 | `x86-capcompare-real.json` |
| n8n SQLite 子程序在真實流程裡切斷網路（10fe446） | 在 dev-c 裡用 `sandbox_netns_sampler.py` 唯讀觀察 `/proc`：15 個 n8n 子程序（程式 sha256 = 這棵樹的 `ha_n8n.SQLITE_CHILD`），14 個在降成 nobody 之後被看到，**全部在自己的網路命名空間、已 chroot**；1 個在兩次掃描之間就結束（看不到降權後的狀態，它的檢查作業成功；有了 10fe446，切不斷網路的子程序會以 3 結束並讓作業失敗）。失敗情境那次沒有 n8n 子程序（砍掉／取消停在 Odoo 轉換，空間與 C-19 只轉 Odoo）。 | `sandbox-netns-arm.json`、`-x86.json`、`-x86-fix.json`、`-capcompare.json` |

## 什麼是模擬的、什麼沒有涵蓋

* 失敗情境裡：中途砍掉＝對真正轉換作業的 systemd unit 送 SIGKILL；空間不足＝在 dev-c 裡把 staging 換成限制大小的 tmpfs（主機磁碟從不填滿）；
  還原失敗＝注入 odoo-db.service 第一次啟動失敗（事後移除 drop-in）；C-19＝在 dev-c 的 PostgreSQL 用 ALTER SYSTEM 設定，事後重設。
* `pull`（從 Docker Hub 下載 PostgreSQL 16）沒有跑：dev-c 依設計沒有網路。
* dev-c 是 Python 3.12.3，所以跑到的是 `os.unshare`；Python < 3.12 的 libc 退路在這裡沒有被執行（那是 .54 Debian 12 的 arm54 小組範圍）。
* ARM 逐列比對沿用 11-23 對同一份備份做的來源擷取 `capture-arm-997c63e7`（驅動程式檢查了綁定：同一個封存 sha256，且與 HA 端指紋 205／205 相同）；
  x86 整庫比對沿用 `capture-x86-7711d584`。
* 沒有涵蓋：實體 ARM 目標（arm54 小組）、HA 網頁上傳（之前的 UI 實測）、商業端到端驗收（負責人）。
* 這次 dev-c 的應用程式資料是測試資料（prodlike_baseline.py），不是正式資料。

## dev-c 收尾狀態（`devc-final-audit.json`，13:35 唯讀稽核）

`true none {}`（network none、沒有對外連接埠）；10／10 個容器 healthy；4 個健康檢查網址 200；基準標記
`before-backup-20261118T175223`／`before-backup-20261118T175342` 都在；沒有匯入資料（沒有 woow_import_probe、測試聯絡人 0、
n8n 工作流程 0）；兩個 PostgreSQL 的 `postgresql.auto.conf` 設定 0；作業標記的容器／卷／網路 0；staging 空；n8n 容器裡沒有憑證匯出檔；
dev-c `/tmp` 沒有 woowbk 檔案；觀察程式全部結束；dev-c 記憶體 956 MB／3.2 GB（開始時 944 MB）。

刻意保留：整合後的引擎留在 dev-c（之前是 `b2f63ce` 引擎，只差上述 3 個檔案；被取代的檔案備份在 dev-c
`/var/backups/woowtech-cockpit-source/20261123T034203256171Z`）；引擎目錄多了這幾次產生的 16 個封存（約 100 MiB，轉換後的測試封存
與還原前安全包），與之前的小組一樣保留；排程計時器 enabled＋active、沒有 schedule.json（排程關閉），與 11-23 odoo-n8n 部署後相同。

---

# 第二次整合與 dev-d EMQX 真實重驗：2026-11-23（integration-2 小組）

同一條分支 `integration/ha-import-batch1-20261123`（只在本機，沒有推送、沒有 PR），接在 integration-1 的 `82ac971` 之後。
`commercial_acceptance` 一律是 `not-complete`。

## 合併了什麼（全部 `--no-ff`，依序）

| 合併 commit | 來源（tip） | 內容 |
| --- | --- | --- |
| `90613fc` | R-EMQX `/tmp/ha-real-fixture-candidate-20261121` 的 `feat/ha-import-batch1`（`ab9e4da`，在本 repo 存成本機分支 `emqx/real-backup-line-20261123`） | EMQX 真實 HA 備份的實驗室工具與證據（11-21～11-23），含 emqx-gaps 的 `f82bbd2..ab9e4da`（FILE 基線的真實規則投遞、子程序時限 2100 秒）。`c8fcbe9` 之後沒有任何 commit 改 `backup-engine/`。 |
| `7c87560` | `feat/odoo-import-mail-reminder-20261123`（`ae5b0d4`） | 擁有者決定 A：正式搬 Odoo 前提醒先停掉 HA 那邊的 Odoo，避免兩邊各寄一次信（只有提示文字，行為不變）。 |
| `d812699` | `test/services-b-final-20261123`（`cde33c2`） | LiteLLM 真實 HA 備份的實驗室工具與證據（attempt 04 通過 24/24）、credential ledger。 |

刻意沒有合併：`test/hermes-real-20261123`、`test/arm54-final-20261123`（還在跑；arm54 要 squash）。Hermes 的儀表板 cookie
覆蓋不在 services-b-final 分支裡，它已經由 hermes-real 收進自己的分支，最後一步跟著 hermes-real 一起進來。

## 合併衝突與處理（只有 R-EMQX 那一次有）

兩條線從 `d06e166` 分開（R-EMQX 328 個 commit、這邊 97 個），有 9 個檔案兩邊都改過。兩邊共同的部分來自相同的 cherry-pick
（patch-id 相同：`6ab87c2=dc1aa7e`、`79dfbc0=6b34dba`、`412124e=4a1f9fd`、`57ae7de=38f5a8c`、`7fb0e1c=61773ec`），所以每個
衝突檔案其實只有**一邊**有自己的修改，逐一證明後整檔取那一邊：

| 檔案 | 取哪一邊 | 理由 |
| --- | --- | --- |
| `tests/e2e/lab/emqx_real_candidate.py` | R-EMQX | 後來真實測試用的就是這版（`1b8f338`、`b727726`、`6f106de`：固定的建置階段標記、可選的 private_capture，拒絕條件不變）；這邊的檔案等於 R-EMQX 在 `61773ec` 的版本。 |
| `tests/e2e/lab/EMQX-REAL-CALLER.md` | R-EMQX | `dea3e13`、`1b8f338` 加的段落；這邊等於 `61773ec` 的版本。 |
| `tests/e2e/lab/ha_real_fixture.py` | 這邊 | 唯一差別是 `7566d44` 加的說明文字；程式碼與真實測試用的完全相同。 |
| `tests/e2e/lab/test_ha_real_fixture.py`、`test_emqx_real_candidate.py` | 這邊 | `7566d44` 是 R-EMQX 版本的嚴格超集（完整讀完來源串流、v3 尾端驗證失敗、截斷、gzip 尾端損壞、公開 EMQX 轉換在內部建置後仍被擋）。這就是把這邊的意圖帶到 R-EMQX 的程式上；在 R-EMQX 的程式上通過 54/54。沒有放寬任何斷言。 |

自動合併、人工檢查：`acceptance-progress-20261120.json` 仍是合法 JSON，這邊改的 64 個值與 R-EMQX 改的 1 個值都在；
`emqx-cold-encrypted-preflight-20261121.json`、`real-fixture-metadata-20261121.json`、`REAL-FIXTURE-PREPARATION.md` 兩邊位元組相同。
其他證據路徑不同，兩邊全部保留。

合併後另外修了一個 R-EMQX 線既有的錯誤：`5d83b24` `run_emqx_adapter_lab.sh` 打包清單裡的 `emqx_candidate_stage.py` 少了
`tests/e2e/lab/` 前綴（`b727726` 帶進來的；`5d83b24` 的 commit 訊息把 `b727726` 的日期寫成 11-22，正確是 2026-11-23 00:19），
tar 會失敗；只改路徑，`test_emqx_adapter_wrapper` 由 5/7 變 7/7。真實擁有者測試用的 `run_emqx_real_owner.sh` 不受影響。

## 單元測試（`unit-tests-step2.json`）

全部在主機上跑，程序內守衛禁止啟動 podman／labpodman／ssh／sudo／systemctl 等，也擋下 `emqx_native_runtime.run_native`
（它會呼叫主機正式環境的 `/usr/bin/podman`）；另有 PATH 擋板。整套測試都在 `/tmp/woowbk-host-heavy-tests.lock` 裡、nice／ionice 下跑。

| 套件 | 結果 |
| --- | --- |
| `tests/backup`（全部，開啟真實 batch-1 HA 備份） | 1454 個：1440 通過、1 略過、13 未通過＝`test_ha_omnigent` 7 個（既有的 SECURITY_BLOCKER，`82ac971` 與 `ab9e4da` 上 id 完全相同）＋`test_litellm_lab_runner` 5 個（守衛自己的誤判；只看執行檔重跑 6/6 通過）＋1 個時間敏感測試（子程序只給 0.3 秒，主機負載約 25 時沒趕上；單獨重跑 3 次 18/18 通過）。`test_ha_b1_real` 5/5。 |
| 略過的那 1 個 | `test_ha_backup.RealBackupTests`：用 20261118 的真實 HA 備份重跑 1/1 通過。 |
| `test_ha_emqx` | 這裡 0 個未通過（`82ac971` 上是 10 個）。不是本小組改的：R-EMQX 的 `ca0a30d`（11-23 04:09）把舊的公開入口測試改成檢查 PRESERVATION_BLOCKER 必須擋下，建置／打包的回歸測試改走內部候選路徑。防護本身沒變：`ha_emqx.convert` 仍丟出 PRESERVATION_BLOCKER。 |
| `node tests/backup-ui.mjs` | 99/99 通過（500 秒）。 |
| `tests/e2e/lab`（兩條線全部 120 個模組，`5d83b24`） | 啟動 1012 個、965 通過。R-COCKPIT 自己的 152/152、兩邊都有的 111/111、services-b 17/17 全過；R-EMQX 自己的 732 個裡 685 通過、45 個需要真的原生執行環境（`run_native`＝主機 podman）而被守衛在啟動前擋下、2 個過期測試（見下）；另有 8 個測試類別（30 個測試）的 setUpClass 就需要原生環境，沒有啟動。被擋下的呼叫共 133 次，全是 `run_native`，沒有任何 podman 程序被啟動。同樣的未通過 id 在合併前的 `ab9e4da` 一模一樣。 |
| 合併前的 EMQX 模擬測試（19 個模組） | 314/314 通過。 |

過期測試：`test_emqx_persisted_values` 2 個，從 R-EMQX 的 `60844f1`（11-22 23:16，二分搜尋找到）開始失敗：證據回執改成固定的在地化文字
（`credential-preflight.txt`，198 位元組，不再含 ASCII 的 `passed`），測試還在找 `credential-preflight.json`，而且拿 `passed`
當作必須出現在回執裡的探針值。依規則（只有供應商原始碼能證明時才改斷言）這裡沒改，留給 EMQX 小組更新探針。

## dev-d 真實重驗（從整合後的樹跑 EMQX）

`emqx-real-restore-20261123/integration-arm-mnesia-attempt1.json`（證據 commit `1646337`）：在 `d812699` 從本工作樹執行
`tests/e2e/lab/run_emqx_real_owner.sh --real-restore-mnesia-acl`。結束碼 0、1057 秒（18:13:59–18:31:36），只有兩行固定輸出
`REAL OWNER RESTORE ROLLBACK PASSED`、`REAL OWNER POSTFLIGHT PASSED`；stderr 0 位元組；dev-d 鎖由這次執行持有；執行中 HEAD 沒變；
這個模式下規則投遞是必跑的。私有回執 `~/.woowbk-lab/emqx-real-owner-evidence-gn1stghl/owner-restore.txt`（0600）的 sha256 與
R-EMQX 先前通過的相同（`ea43e157...5b0e`）。執行後 dev-d：`isolation true none {}`。

範圍照實說：真實的 ARM 加密冷備份走**內部候選**建置／打包路徑（公開的 HA EMQX 匯入仍被 PRESERVATION_BLOCKER 擋住）進到 dev-d 的
EMQX，含匯入的 Mnesia ACL；MQTT／API／負面／ACL／物件檢查、真實規則投遞（HTTP 動作用廠商計數器證明，目標是備份原本的位址）、
注入一次啟動失敗觸發自動回復、重新啟動一輪、清理與事後檢查。模擬的只有回復的觸發。

# 第三次整合（最後整合，進行中）：2026-11-23（integration-3 小組）

同一條分支 `integration/ha-import-batch1-20261123`（只在本機，沒有推送、沒有 PR），接在 integration-2 的 `a8ed026` 之後。
這一組**只合併、只跑單元測試**，不做實驗室的真實還原（dev-d、dev-e、.54 由各自的負責小組使用；最後的真實重驗是另一個步驟）。
`commercial_acceptance` 一律是 `not-complete`。

## 合併了什麼（全部 `--no-ff`，依序）

| 合併 commit | 來源（tip） | 內容 |
| --- | --- | --- |
| `1072954` | `test/hermes-real-20261123`（`e52ffd5`） | Hermes 真實 HA 備份的實驗室工具（`hermes_real_ha.py`、`hermes_real_capture.py`）、儀表板 cookie 覆蓋（services-b 的 4 個 commit 的複本）、第 1–12 次嘗試的證據；第 7、8、11、12 次通過。 |
| `315ec8b` | `test/services-a2-20261123`（`1214226`） | Headscale 完整產品流程（ARM 第 1 次 101/101、x86 第 3 次 96/96，失敗的 x86 第 1、2 次保留）、Omnigent x86 第 5 次、`dev_d_guard.py`；只有 `tests/e2e/lab`。 |
| `ae5420d` | `feat/ha-import-opendesign-20261123`（`13c83f3`） | OpenDesign 匯入（`ha_opendesign.py`、haapps `open-design`、hasqlite 的 opendesign 讀取、頁面、文件、CONTRACT）、dev-e 實驗室腳本、`opendesign_full_flow.py` 與 dev-e 證據（第 3 次 85/85）。 |

## 合併衝突與處理

* hermes-real、services-a-2：沒有衝突；分支改的 18／14 個檔案在整合分支與分支 tip 位元組完全相同。
* OpenDesign：只有 `tests/e2e/lab/README.md` 衝突：兩邊在同一個位置（dev-d 一節的最後）各加了一節（hermes-real 的
  「Hermes 真實還原」小節、OpenDesign 的「dev-e」一節）。兩節都保留，Hermes 在前（它屬於 dev-d 一節）。逐行證明：這邊加的 57 行、
  那邊加的 82 行全部在結果裡，基準中被刪的只有 1 行（那邊把開頭的介紹改成也提到 dev-e），沒有任何一邊都沒有的行。
  `backup/backup.js`（這邊：Odoo 寄信提醒 `7c87560`；那邊：HA 對照表與 `haOpenDesignFacts`）、`docs/backup.md`、`tests/backup-ui.mjs`
  兩邊改的位置不同、自動合併；三個檔案都驗證 patch-id(基準→那邊) = patch-id(這邊→結果)，且 patch-id(基準→這邊) = patch-id(那邊→結果)。
  其餘 26 個只有那邊改的檔案等於 `13c83f3` 的版本。
* lab/batch2-dev-e-20261123 之後的兩個 commit（`00b0785`、`2b85b92`，以及更晚的）不在這次合併裡，會跟著第二批的分支進來。

## 單元測試（`unit-tests-step3.json`，測試 commit `ae5420d`）

守衛與做法同 integration-2（程序內禁止啟動 podman／labpodman／ssh／sudo／systemctl 等，擋下 `emqx_native_runtime.run_native`，
PATH 擋板）；整套測試都在 `/tmp/woowbk-host-heavy-tests.lock` 裡、nice／ionice 下跑。每次合併在提交前先跑受影響的模組
（63／54／63＋81 個，全部通過，0 次被擋）。

| 套件 | 結果 |
| --- | --- |
| `tests/backup`（全部，開啟真實 batch-1 HA 備份） | 1471 個：1458 通過、1 略過、12 未通過＝`test_ha_omnigent` 7 個（既有的 SECURITY_BLOCKER，與 integration-2 相同的 id）＋`test_litellm_lab_runner` 5 個（本守衛的誤擋：測試的假子程序參數裡有 podman；`--exe-only` 守衛下 6/6 通過，只啟動假的 `child`）。integration-2 多 1 個的時間性偶發失敗這次沒有出現。 |
| 略過的那 1 個 | `test_ha_backup.RealBackupTests`：用 20261118 的真實 HA 備份重跑 1/1 通過。 |
| `node tests/backup-ui.mjs` | 100/100 通過（含 OpenDesign 檢查卡片的情境；integration-2 時是 99 個）。 |
| `tests/e2e/lab`（兩條線全部模組） | 啟動 1090 個、1043 通過；未通過的 73 筆紀錄與 integration-2（`5d83b24`）**完全相同**：71 個是 R-EMQX 需要 `run_native`（主機正式環境的 `/usr/bin/podman`，被守衛擋下，133 次）的測試，其中 8 個整個類別在 setUpClass 就停；2 個是過期的 `test_emqx_persisted_values`（R-EMQX `60844f1` 起回執改成 `.txt`，留給 EMQX 小組）。新增的 78 個測試全部通過。 |

沒有跑（照規則）：需要 `run_native` 的實驗室測試（上面那 71 筆），它們只能在實驗室裡跑。

提交前掃描：三次合併帶進來的 61 個檔案，以既有的 `ha_import_b1_e2e.Secrets` 讀出的 30 個實驗室值（原文與 JSON 跳脫）搜尋，
0 命中；5 個 HA 金鑰形狀的字串是文件與頁面上的格式範例、頁面測試的常數 `HA_KEY`／`HA_WRONG_KEY`，在 `a8ed026` 就已存在、內容沒變。

## 給主線與擁有者的紀錄

* hermes-real 的獨立驗證（19:57）全部確認。它提醒的兩點：`1eb0933`（Python < 3.12 改用 libc `unshare`）已經在這條分支上
  （由 integration-1 的 `7790cf8` 帶進來）；Hermes FTS5 安全審查的說法：`8b47124` 的 commit 訊息記錄了擁有者授權的獨立審查，
  而小組規則仍把「人工的 Hermes 安全審查」列為人工項目。這一組沒有改 hermes-real 的 `status.json`，最後的說法請主線／擁有者決定。
* services-a-2 的驗證者提醒的用語照抄：「真實 RPi5 客戶端」其實是這台主機上的 x86-64 tailscaled 1.104.7（加入 RPi5 的 Headscale
  後的實驗室容器），測試時在 dev-d 裡跑；「頁面流程」是頁面送出的 root helper 指令（瀏覽器上傳改成複製檔案）；found-state 的
  ha-check 斷言（`c5f9c92` → `5c9fd64`）改動引用的是產品原始碼而不是廠商原始碼，是實驗室的預期值、不是公開的防護，已列為擁有者的發現。
* OpenDesign 仍開著（不是阻擋）：`projects.metadata_json.baseDir` 改寫（目前只是警告）、測試模式不會暫停 OpenDesign 的例行工作（只有提醒）。

## 第三次整合（續）：code-server、第二批實驗室紀錄與 share 來源備份

| 合併 commit | 來源（tip） | 內容 |
| --- | --- | --- |
| `88e7e6b` | `feat/ha-import-code-server-20261123`（`f20ac84`） | code-server 匯入（`ha_codeserver.py`、haapps `woow-code-server`、`habackup.NEVER_READ` 加上代理程式的登入檔）、頁面（code-server 事實卡、Cloudflare Tunnel 與 `woow_mcp_*` 附加元件「不會搬過來」的提醒）、文件、CONTRACT、dev-e 目錄項目、`codeserver_full_flow.py` 與證據（第 1 次真實嘗試 87/87）。 |
| `fb284b8` | `lab/batch2-dev-e-20261123`（`8de186d`） | dev-e 的 code-server 與 Nextcloud 實驗室紀錄（部署、基準 16/16 與 14/14、輪替紀錄、`test_batch2_lab.py`）；只有 `tests/e2e/lab`。 |
| `3579716` | `evidence/ha-b2-nc-share-20261123`（`24a045e`） | 從擁有者的 x86 展示機 HA 做的第二批真實來源備份紀錄（`f884a0a`、`1c76ded`）與「含 share 資料夾」的 Nextcloud HA 備份（4,467,947,520 位元組，sha256 `2dcfc676…ded9d`，兩邊相同）的腳本與證據；這是**來源**，不是匯入。 |

**code-server 的衝突**（5 個檔案、diff3 共 20 段，全部是「兩邊各把自己的應用加進同一個清單」，基準 `d812699`）：
`haapps.IMPORTERS` 兩個項目都留（OpenDesign 在前）；`backup.js` 的 `HA_APP_NAMES`、`HA_SHORT`、`HA_FACTS`、`HA_LARGE`
都是同一位置的純插入，兩邊都留（這邊在前），`HA_LARGE` 的註解重新斷行；`HA_CODE` 手動合併（每個應用一行，註解同時寫
OpenDesign 與 code-server 會執行的程式）；`docs/backup.md` 開頭那句手動改成「Headscale、OpenDesign 與 code-server」，版本檢查
那一行、測試模式表格、匯入對照表與各應用的段落兩邊都留；CONTRACT 兩段修訂說明、列舉值、`HaCheck` 依序列出
`open-design?{…}` 與 `woow-code-server?{…}`（括號讓 OpenDesign 變成中間項目後仍然成對）；`tests/backup-ui.mjs` 兩組 fixture、
兩個第二批的情境，兩句產品清單改成「…、OpenDesign、code-server」。證明：每個檔案和「這邊＋那邊的修改」不一樣的行
只有這些合併後的行；只有那邊改的 8 個檔案等於 `f20ac84`，只有這邊改的 45 個不變；第二批實驗室檔案兩邊相同，只有
`batch2_baseline.py` 取 `2b85b92`（同一條實驗室分支較新的 commit，這邊的 `a9dc46b` 是它的祖先）；`tests/e2e/lab/README.md` 等於
那邊的版本加上這邊的 Hermes 一節（一個區塊、沒有刪除任何行）。

**第二批實驗室分支**：沒有文字衝突；10 個檔案中 9 個等於 `8de186d`。更正：`fb284b8` 的 commit 訊息寫「這 10 個檔案在
`2b85b92` 之後這邊都沒改」，`tests/e2e/lab/README.md` 例外（這邊有 hermes-real 的一節），git 自動合併；證明 patch-id 兩個方向都相同，
結果與那邊相比只多 Hermes 那一節。歷史沒有改寫。

**測試**：合併前（暫存的合併結果）受影響的 `tests/backup` 模組 167 個（含真實 batch-1 HA 備份），0 個未通過、1 個略過（20261118
的重跑，整套時另外跑）；`test_batch2_lab`＋`test_dev_d_guard` 19／26 個全過。`node tests/backup-ui.mjs`：20:48 那次在主機負載 53 時
只出現 Playwright 10 秒逾時，由本組停止、不算；22:28–22:41（負載約 24–30）在 `fb284b8` 重跑 **101/101**（含 OpenDesign 與
code-server 兩個第二批情境）。整套 `tests/backup` 與 `tests/e2e/lab` 在 `fb284b8`（本組另一個工作樹，同一個 commit）：`tests/backup` 1488 個：1475 通過、1 略過、12 未通過，與第一步完全相同的 id（`test_ha_omnigent` 7＋`test_litellm_lab_runner` 5，新加的 17 個 code-server 測試全過）；20261118 重跑 1/1；`tests/e2e/lab` 啟動 1097 個、1050 通過，未通過的 73 筆與第一步、integration-2 完全相同（新加的 7 個 `test_batch2_lab` 全過）。之後的 `3579716` 只加了 33 個實驗室腳本與證據檔（沒有單元測試模組），上面的結果不變。證據 `unit-tests-step3b.json`。

**驗證者的提醒照抄**：
* OpenDesign（20:36）：第 2 次失敗後 `f4a3c16` 放寬了兩項實驗室檢查（`RUNTIME_KEPT` 排除 30 個執行期項目、外洩搜尋略過以 `/`
  開頭的值與一般網址），依據是量測與分析，不是規則 2 要求的廠商檔案行號；真實備份沒有搬任何第三方憑證；自動回復還原的是同一份
  轉換後備份，資料檢查分不出回復與成功；瀏覽器頁面沒有在 dev-e 上測。
* code-server（21:30）：自動回復同樣是把同一份轉換後備份再還原一次（只證明回復路徑，手動回復才證明資料互換）；「MCP 值已收集」
  是空集合（0 個值）；工作區搬移、延伸模組搬移、ARM、真正的瀏覽器頁面、正式主機的目錄項目都沒有實測（該線已說明）。
