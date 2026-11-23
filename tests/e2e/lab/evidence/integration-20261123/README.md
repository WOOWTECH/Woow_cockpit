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
