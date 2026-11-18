# 驗證與截圖

## 自動測試

```bash
python3 -m unittest discover -s tests -t . -v
python3 scripts/check_source.py
bash -n scripts/bootstrap-ubuntu.sh scripts/build-podman.sh
node --check scripts/capture.mjs
node --check backup/backup.js
npm ci
npx playwright-core install chromium
npm test
```

`tests/` 是 Python 套件，`unittest` 必須加 `-t .` 從 repository 根目錄探索；CI 使用同一個指令。

`unittest` 在暫存根目錄檢查安裝、重複安裝、純 HTML／gzip 原生入口、檔案與權限還原、保留客戶檔、上游升級後重新套用、拒絕舊回退、symlink 防護、寫入失敗回復、損壞備份與舊版拒絕；備份套件另檢查安裝權限、helper 的信任檢查、`--no-backup`、示範目錄項目，以及安裝器從不管理備份執行資料。不需要 sudo，不會碰本機 Cockpit。

瀏覽器測試將來源安裝到另一個暫存根目錄，以限制 CSP 提供本機靜態服務，檢查1440／1024／390／360px的全白圖集、缺圖提示、完整圖連結、SVG圖示及無橫向溢出，再驗證加入一張本機圖片。CI執行同一組測試，不需主機密碼。

CI 不部署真實 Ubuntu 服務、不登入參考主機、不測試完整災難復原。參考主機的真實驗證範圍見 current-state。

## 服務管理測試

`tests/test_services.py` 以模擬指令結果驗證權限、固定指令參數、使用者身分、日誌範圍、輸出過濾、停止中的 Quadlet、錯誤／逾時、並行鎖定及失敗狀態。未命名模板會讓 systemctl 的批次 show 提前結束，因此有專門的回歸案例，避免後方服務被漏列。此檔 11 項；加上安裝器的 `tests/test_manage.py`（28 項，已含備份套件的安裝測試）共 39 項 Python 測試。

`tests/services-ui.mjs` 提供本機 Cockpit API fixture，測試9個行為：未授權資料隔離、停止服務與分頁、確認／取消、stdout錯誤、關鍵服務保護、日誌文字安全、擁有者導覽、桌面／手機版面，以及斷線後重新連線而不重送操作。它不執行真實主機操作；與圖集測試同由 `npm test` 執行。

`tests/managed-owners.mjs` 另以原生 Application 的事件介面驗證4個問題：All 自動載入、首次指定 UID、提升權限後載入，以及舊連線不得清掉新連線。安裝器另測試124版套用、125版保留原生檔案，以及 JS 備份／回退。完整原生建置可執行 `bash scripts/build-podman.sh`；需要 npm 下載鎖定版本的建置依賴。

真實驗證另使用三個獨立測試單元：一般使用者服務、使用者 Quadlet，以及系統服務。從已登入的 Cockpit 頁面點擊啟動／重新啟動／停止，再由 systemd 狀態及實際 PID 交叉確認；Quadlet 另確認停止後容器移除但服務仍可再啟動。驗證完成後移除測試單元與容器，不對正式應用進行停機測試。

## 備份與還原測試

分三層：不需設備的單元與來源檢查、頁面 fixture 瀏覽器測試，以及兩台隔離實驗室設備上的端到端測試。**備份還原測試不得使用正式應用或其資料；正式主機上只允許經負責人同意的示範應用實測（見 [current-state.md](current-state.md)）。**

### 單元測試與來源檢查

`tests/backup/` 涵蓋封存格式與惡意封存檔、備份內資料卷與映像封存（巢狀 tar）的檢查與重新產生、金鑰、本機儲存、應用目錄驗證、以擁有者身分執行指令、`quadlet-postgres` 轉接器、備份／還原／驗證流程、背景作業、中斷復原與作業紀錄保留，以及 helper 的 JSON 介面；外部指令以假的執行器模擬。`tests/test_manage.py` 檢查備份套件的安裝，`tests/e2e/test_demo_fixture.py` 離線檢查示範應用。這些都包含在上方的 `unittest` 指令中。

需要 `age` 的測試在沒有 age 的主機上會略過。要完整執行，使用含 age 與 zstd 的測試映像（只用實驗室的獨立儲存，啟動容器前先確認 `free -m` 的 available 至少 1200 MB）：

```bash
LP=~/.woowbk-lab/bin/labpodman
# 建置一次
$LP build --memory 512m -t localhost/woowbk-testrunner:noble -f tests/backup/Containerfile.testrunner tests/backup
# 以 root 執行
$LP run --rm --memory 384m -e PYTHONDONTWRITEBYTECODE=1 -v "$PWD":/src:ro -w /src \
  localhost/woowbk-testrunner:noble python3 -m unittest discover -s tests -t . -v
# 以一般使用者執行（另外涵蓋只適用於非 root 的測試）
$LP run --rm --memory 384m --user 1000:1000 -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 -v "$PWD":/src:ro -w /src \
  localhost/woowbk-testrunner:noble python3 -m unittest discover -s tests -t . -v
```

`scripts/check_source.py` 另檢查備份頁的 manifest、CSP 與 DOM 寫入方式、每個引擎原始檔（shebang、語法、不使用 shell），並以引擎的驗證程式檢查示範目錄項目。

Home Assistant 備份（`tests/backup/test_ha_*.py`）讀取 `tests/backup/fixtures/ha/` 的小型 HA 備份：它們由真正的 securetar 函式庫產生（v1、v2、v3、未加密、HA「下載」得到的解密副本；產生方式見該資料夾的 README），測試解密結果與函式庫逐位元組相同、錯誤金鑰、截斷與竄改、惡意的外層與內層 tar，以及上傳、`list`、`ha-delete` 與作業日誌遮蔽 HA 金鑰。需要 `python3-nacl` 與 `python3-cryptography`（測試映像與 CI 都有；CI 設定 `WOOWBK_REQUIRE_HA_CRYPTO=1`，缺少時不會略過而是失敗）；主機沒有時這些測試會略過。為這個功能建立的真實 HA 備份從不提交；要對它們測試，設定 `WOOWBK_HA_FIXTURES`（三個備份所在的資料夾）與 `WOOWBK_HA_KEY`（它們的金鑰），`RealBackupTests` 會完整串流讀取每個項目。HA 匯入的檢查與轉換作業（`test_ha_tempctr.py`、`test_ha_odoo.py`、`test_ha_n8n.py`、`test_ha_import.py`，以及 `test_ha_cli.py` 的新指令）用假的執行器與小型 tar／SQLite 夾具：暫用容器的完整命令列、Quadlet 的機密與環境變數解析、清理與中斷後的清除、Odoo 模組版本判斷與各種擋下的原因、附加元件 tar 的單次讀取（資料庫叢集、附件、自訂模組，HA 密碼檔從不讀取）、n8n 的 SQLite 讀取（擁有者、筆數、檢視表從不執行）、需要修正的工作流程、原生模組檢查、作業紀錄的階段名稱、HA 金鑰原樣保存並在第一行日誌前遮蔽、`ha-imports.json`，以及檢查／轉換流程（容器步驟以替身代替）。審查修正（2026-11-18）之後另有：`test_ha_flows.py` 用模擬應用擁有者 podman 的替身跑完整的 Odoo 與 n8n 轉換（真正的 `ha_odoo.convert`／`ha_n8n.convert`、`TempObjects`、`Cluster`；psql 替身照 PostgreSQL 的規則拒絕交易區塊中的 ALTER SYSTEM，n8n 筆數查詢拒絕超過 100 個函式參數），驗證 HA 的 PostgreSQL 不可信的處理（設定檔換成已知的、停用的設定、noexec 資料卷、唯讀根目錄、以 odoo 角色從標準輸入還原、需要超級使用者的物件被拒絕）、沿用設定、網站網域、neutralize 掛載的模組資料夾與 `verify_converted` 的每一項；`test_ha_space.py` 測空間與取消的監看（低於下限時立刻終止暫用容器、取消要求、執行中的命令在一秒內停止、`--cpus`）；n8n 的 SQLite 由降權的子程序在自己的複本上讀取（虛擬表不讀、-shm 不用、過大的工作流程不分析、取消時子程序被終止）；符號連結鏈不能往上爬；`ha-imports.json` 接受轉換產生的任何內容；轉換備份不算在保留份數與「最近備份」裡。容器步驟本身在實驗室設備 dev-c 上實測（見下方「HA 匯入」）。

2026-11-13 最終回歸：主機（已安裝 age）471 項通過、0 項略過；測試映像以 root 執行 471 項通過、3 項略過（只適用非 root），以 uid 1000 執行 471 項通過、0 項略過。`check_source.py` 通過（32 個資源參照、17 個引擎原始檔、示範目錄的 3 個 Quadlet 範本）。較早的整合輪為 317 項，當時主機沒有 age，50 項略過。

### 頁面 fixture 測試

`tests/backup-ui.mjs`（包含在 `npm test`）以假的 `window.cockpit` 記錄每次 helper 呼叫並模擬上傳與下載通道，不會啟動任何程序。測試金鑰設定與緊急金鑰（只顯示一次；確認後重新下載要先經過確認對話框，且不顯示金鑰）、建立備份與下載、512 KiB 分段與 4 MiB 確認視窗的上傳與取消、上傳後檢查逾時時保留上傳並可「重新確認」、上傳進行中或待確認時不被其他還原取代、需要金鑰的上傳還原、錯誤金鑰不會被保存、自動回復結果、結果頁依實際發生的事說明（含「不建立還原前備份，直接還原」）、還原還原前備份時不承諾建立新的還原前備份、全新部署的確認說明、重新載入後回到作業與中斷指引、`busy`、需要管理員權限、空目錄、刪除與取消的確認、驗證要求金鑰、惡意字串只以文字顯示、背景更新不打斷輸入、健康檢查未通過的應用顯示「異常」、跟隨 Cockpit 深色主題且各畫面對比可讀、1440／1024／768／390／360／320px 版面、鍵盤焦點、斷線與 helper 缺失、下載失敗，以及原始碼規則（只用 DOM 建立內容、固定 helper、金鑰只在標準輸入的 `key` 欄位、無遠端資源）。2026-11-13 最終回歸（commit 552b5fe）30／30 通過（`npm test` 共 49／49：managed-owners 4、preview 6、services-ui 9、backup-ui 30）；之後加入深色主題的 commit 3bc4b27 上為 31／31。2026-11-14（`feat/backup-strengthen`）加入：不加密的備份不需要金鑰但要另外確認、「預設加密備份」的確認對話框、每份備份的「已加密／未加密」與「來源未驗證」標示、下載選單與「下載未加密版本」（警告、作業、自動下載、到期與刪除，含需要緊急金鑰的情況）、未加密上傳的額外確認、資料核對逐項表格與差異、停機時間、逐項驗證的結果、整個執行個體的顯示、各應用的備份空間（引擎提供或由清單計算）、清理備份（預覽、受保護的備份、確認刪除）、應用設定（掃描、草稿、模式切換、JSON 檢查、差異、安裝與移除）、舊版引擎不支援時的說明、惡意字串，以及新畫面在深色與淺色主題的對比、1440–320px 版面與鍵盤操作；共 52／52 通過（chromium-1248 與 CI 使用的 chromium_headless_shell-1208 各一次）。

```bash
PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chrome node tests/backup-ui.mjs
# 選用：保存截圖
BACKUP_UI_SCREENSHOTS=.local/backup-ui node tests/backup-ui.mjs
```

### 實驗室設備端到端測試

兩台隔離的「設備」是以 systemd 為 PID 1 的 rootless 容器，內含 Ubuntu 24.04、Cockpit 362、巢狀 rootless Podman、age 與 zstd：`woowbk-dev-a`（https://127.0.0.1:19091，appowner UID 1001，已部署示範應用）與 `woowbk-dev-b`（https://127.0.0.1:19092，appowner UID 1007，跨設備還原目標）。所有容器操作只經 `~/.woowbk-lab/bin/labpodman`（獨立儲存根目錄），看不到也不影響正式主機的容器、資料卷、映像與服務；不使用 sudo。`devadmin` 的密碼與 dev-a 的緊急金鑰都是拋棄式實驗室憑證，存於 `~/.woowbk-lab/secrets/`（0600），不出現在輸出或證據中。完整說明見 [tests/e2e/lab/README.md](../tests/e2e/lab/README.md)。

```bash
tests/e2e/lab/build.sh                                       # 建置設備映像
tests/e2e/lab/up.sh a && tests/e2e/lab/up.sh b               # 啟動前確認主機可用記憶體 ≥ 1200 MB
tests/e2e/lab/verify-device.sh a && tests/e2e/lab/verify-device.sh b
tests/e2e/lab/deploy-demo.sh a --notes 12 --files 4          # 只在 dev-a 部署示範應用
tests/e2e/lab/deploy-src.sh a && tests/e2e/lab/deploy-src.sh b   # 安裝目前工作樹（含 --backup-demo-catalog）

python3 -I tests/e2e/lab/cli_e2e.py all                     # 以頁面相同的方式呼叫已安裝的 helper
node tests/e2e/lab/ui_e2e.mjs all                            # 以 Playwright 操作真正的 Cockpit 362 頁面
python3 -I tests/e2e/lab/hardening.py all                    # 強化測試 H1–H7、sec1、fidelity、fresh 與洩漏檢查
python3 -I tests/e2e/lab/schedule_e2e.py all                 # 排程備份：真正的計時器與檢查服務、時段、等待、保留、相容性
python3 -I tests/e2e/lab/race_probe.py a                     # 作業紀錄競態探測（b 同理）
node tests/e2e/lab/upload_window.mjs                         # H8：上傳視窗與分段大小的評估（只在測試瀏覽器內修改）
```

整合輪（2026-11-14，`feat/backup-strengthen`，兩台設備都以 `deploy-src.sh` 部署工作樹）：除了 `cli_e2e.py`、`dirs_e2e.py`、`format_e2e.py`、`hardening.py`，另以 `tests/e2e/lab/strengthen_e2e.py`（應用設定草稿的安裝、資料摘要的原位與跨設備比對、刻意損毀的資料、深入驗證、PostgreSQL 整個執行個體、沒有金鑰的設備、保留原則、被修改的 `backup.json`、停機量測）與 `tests/e2e/lab/strengthen_ui.mjs`（以 Playwright 操作兩台設備上真正的 Cockpit 頁面：應用設定、清理備份、加密選擇、頁面下載的 `.tar` 以 tar 與 README 指令解開、未加密副本、深入驗證、資料核對表、未加密上傳的額外確認）驗證。單元測試主機 823 項通過；測試映像以 root 823 項通過（4 項略過：3 項只適用非 root、1 項需要實驗室的參考主機目錄），以 uid 1000 823 項通過（1 項略過：同一個參考目錄）。結果與證據位置見 [CONTRACT.md](backup/CONTRACT.md) 第 13 節與 [tests/e2e/lab/README.md](../tests/e2e/lab/README.md)。

審查修正後的最終回歸（2026-11-14，同一分支；修正了審查指出的 H1、H2、M1–M4、L1–L8、F1–F8、F10、F11、F14、F16、F17，每項都有回歸測試）：較長的情境在第 3 版（除最後一項以外的全部修正）上執行；最後一項修改（還原時資料摘要不一致會再讀一次）之後重新部署第 4 版，也就是最後的工作樹，再跑單元測試、`cli_e2e.py` 與會用到這項修改的 `strengthen_e2e.py` 情境。`hardening.py`、`format_e2e.py`、`dirs_e2e.py` 以夾具目錄（沒有資料摘要）執行，走不到這項修改。每次部署後已安裝的 28 個引擎、helper、頁面與 VERSION 檔案都與當時的工作樹逐一比對 sha256 相同。證據在 `~/.woowbk-lab/evidence/strengthen-final/`（各執行器的紀錄、`runs.json` 索引、`builds.txt` 版本與執行對照、部署與雜湊比對、洩漏掃描）。

| 項目 | 結果 |
| --- | --- |
| 單元測試（最後一版） | 主機 856 項通過；測試映像 root 856 項通過（4 項略過：3 項只適用非 root、1 項需要參考主機目錄）、uid 1000 856 項通過（1 項略過：同一個目錄）；`check_source.py` 通過；`node --check` 通過 |
| 頁面 fixture（`backup-ui.mjs`，chromium-1248） | 52／52 |
| `digest_sql_probe.py`（postgres:16-alpine 16.16） | 9／9：修正前的寫法以超級使用者身分執行資料表擁有者的型別轉換（`COPY … TO PROGRAM` 寫出 `postgres super=true`），引擎的 SQL 不會；其他資料表的摘要與修正前相同；名為 `t` 的欄位不再讓其他欄位漏掉；SQL_ASCII 與 LATIN1 資料庫 |
| `cli_e2e.py all` | 122／122：s1 29、s2 22、faults 11、s3 8、s2-again 22、f8 10、f9 9、cancel 6、leaks 5（最後一版與前一版各跑一次，都全部通過） |
| `hardening.py all`（`H7_FULL=0`） | 551／551：h1 325、h2 13、h3 28、h4 48、h5 15、h6 12、h7 13、sec1 26、fidelity 21、fresh 43、leaks 7（h4 比整合輪少 1 項：這次在 stop 階段終止時寫入服務還沒停止，「終止後服務停著、由復原重新啟動」這項條件檢查不適用，改記錄在紀錄中） |
| `format_e2e.py all` | 105／105：v1 7、encrypted 21、plain 27、export 20、deep 6、partial 7、cleanup 17 |
| `dirs_e2e.py all` | 255／255：prep 18、d1 29、d3 18、d4 29、d5 107、d6 11、d7 16、d2 22、leaks 5（`prep` 換回不含資料摘要的夾具，資料摘要由下一列涵蓋） |
| `strengthen_e2e.py` | catalog-apply 28／28、digests 38／38、instance 53／53、keyless 19／19、retention 16／16、deep 19／19、tampered-json 10／10、mismatch 18／18；最後一版另跑 mismatch 24／24（加上「寫入者仍在時還原」的情況：資料仍在變動，這一項未比對、還原完成）、digests 38／38、instance 53／53，最後 cleanup 55／55。第一次 mismatch 只過 11／15：另一個容器的寫入者在應用容器停止後有幾秒連不上資料庫，還原前備份兩次讀取相同而保存了摘要，回復時它又寫入兩列，回復失敗、應用停在暫時停用（之後以那份還原前備份還原成功）；因此驅動程式加上資料庫容器內的寫入者，引擎在還原時遇到不一致會再讀一次（見 [CONTRACT.md](backup/CONTRACT.md) 第 9 節） |
| `strengthen_ui.mjs`（真正的 Cockpit 362 頁面） | catalog 16／16；cleanup 10、backups 26、devb 9、cleanup-lab 7（52／52） |
| 洩漏掃描 | 各執行器的 leaks 情境都通過；主機上這一輪 622 個證據檔不含實驗室密碼、dev-a 緊急金鑰或 age 私鑰格式 |
| 設備最後的狀態 | 兩台都是最後一版（28 個檔案與工作樹相同），目錄項目換回夾具（只有 http-json 核對），woowbk-inst 已移除，預設加密備份開啟、保留原則為全部保留、沒有作業、暫存與未加密副本都是空的；dev-a 保留 34 份各執行器仍參照的備份，dev-b 1 份 |

排程備份（2026-11-17，`feat/backup-schedule`）。第一輪（c455a07 加上 `schedule_e2e.py`）找到兩個產品問題：已停止的應用讓整次排程備份失敗（應略過並標示部分完成），以及安裝後第一次檢查前、開機已久的設備會誤報「排程檢查沒有在執行」；兩者都在 ad7858e 修正（引擎另改以 PID 1 啟動後的秒數為開機時間，並加上設備時間的 `local` 文字、`schedule.defaults`、tick 服務的 `StandardError=journal` 與對遮蔽計時器的處理）。第二輪在 ad7858e 上：dev-a 先以安裝程式的回退回到 2026.11.15.2 再部署（新增單元的交易），dev-b 從第一輪的工作樹升級，排程情境全部通過，接著跑完整的實驗室回歸。systemd 255 在 `LogLevelMax=notice` 時連 PID 1 對 tick 服務的 Starting／Finished 都不寫（兩輪各 5 次檢查 0 行；沒有這個設定的對照單元每次 3 行）。實驗室設備的 `/proc/uptime` 與 `CLOCK_BOOTTIME` 是主機的開機時間，引擎改用 PID 1 的啟動時間後，`reboot` 以真正的 `labpodman restart` 證明 PID 1 未滿 10 分鐘的檢查都不補做、滿 10 分鐘後第一次檢查才補做。證據在 `~/.woowbk-lab/evidence/schedule/` 與各執行器的目錄。

| 項目（2026-11-17 第二輪，ad7858e） | 結果 |
| --- | --- |
| `schedule_e2e.py` | install 29、timer 17、fast 20、busy 15、timezone 15、run-now 19、retention 11、partial 19、kit-gate 20、compat 31、noise 7、reboot 24、cleanup 13，全部通過 |
| `hardening.py h7`（`H7_FULL=0`，新增單元的交易） | 23／23 |
| `verify-device.sh a`、`b` | 各 10 項通過 |
| `cli_e2e.py all` | 122／122：s1 29、s2 22、faults 11、s3 8、s2-again 22、f8 10、f9 9、cancel 6、leaks 5 |
| `hardening.py all`（`H7_FULL=0`） | 588／588：h1 327、h2 13、space 25、h3 28、h4 48、h5 15、h6 12、h7 23、sec1 26、fidelity 21、fresh 43、leaks 7 |
| `format_e2e.py all` | 105／105：v1 7、encrypted 21、plain 27、export 20、deep 6、partial 7、cleanup 17 |
| `dirs_e2e.py all` | 257／257：prep 20、d1 29、d3 18、d4 29、d5 107、d6 11、d7 16、d2 22、leaks 5 |
| `ui_e2e.mjs all` | 29／29（admin、s1、s2） |
| `race_probe.py a`、`b` | 各 11／11（各 110 個作業，0 個被誤判） |
| `digest_sql_probe.py` | 9／9 |
| `strengthen_ui.mjs` | catalog 16／16；cleanup 9／10、backups 26／26、devb 9／9、cleanup-lab 45／45；cleanup 重跑 11／11（見下） |
| `strengthen_e2e.py` | 205／205：catalog-apply 28、digests 38、mismatch 22、deep 19、instance 53、keyless 19、retention 16、tampered-json 10；cleanup 197／197 |
| `upload_window.mjs`（H8） | 18 次上傳、0 個錯誤（6 種視窗／分段設定各 3 次，到 dev-b、停在金鑰步驟後刪除）；預設的 4 MiB／512 KiB 中位數 15.1 MB/s，主機 CPU 約 97% 忙碌 |
| 離線夾具測試（`tests/e2e`） | 35／35 |

`strengthen_ui.mjs cleanup` 第一次 9／10 是執行順序的問題，不是引擎：`ui_e2e.mjs s1` 在建立頁保留預設的全選，dev-a 上的備份含 woowbk-demo、woowbk-dirs、woowbk-inst，另外兩個應用保留全部，所以它不是 woowbk-demo「保留最新 5 份」的候選（CONTRACT §8：多個應用的備份在任一應用仍需要時保留），而這項檢查假設 woowbk-demo 的手動備份都只含它（候選數 = 手動份數 − 5）。刪除那份測試備份、補 6 份只含 woowbk-demo 的備份後重跑 11／11，之後刪除補的備份。

HA 匯入（2026-11-18～19，`feat/ha-import` 177c8c6，2026.11.19.1 的產品程式）。先在 dev-c 以真正的頁面匯入一次（見下方「HA 匯入（dev-c）」），再在 dev-a、dev-b 部署同一個工作樹跑原有功能的完整回歸，兩台各 36 個已安裝檔案與工作樹 sha256 相同。這次 strengthen 排在 schedule 之前，和 11-17 的順序不同。證據在 `~/.woowbk-lab/evidence/final-ha-import/20261118T151246Z/`。

| 項目（2026-11-19，177c8c6） | 結果 |
| --- | --- |
| `cli_e2e.py all` | 122／122：s1 29、s2 22、faults 11、s3 8、s2-again 22、f8 10、f9 9、cancel 6、leaks 5 |
| `dirs_e2e.py all` | 255／255：prep 18、d1 29、d3 18、d4 29、d5 107、d6 11、d7 16、d2 22、leaks 5 |
| `hardening.py all`（`H7_FULL=0`） | 584／584：h1 327、h2 13、space 25、h3 28、h4 48、h5 15、h6 12、h7 19、sec1 26、fidelity 21、fresh 43、leaks 7 |
| `format_e2e.py all` | 105／105：v1 7、encrypted 21、plain 27、export 20、deep 6、partial 7、cleanup 17 |
| `strengthen_ui.mjs` | catalog 16／16（在 catalog-apply 之前）；cleanup 10／10、backups 26／26、devb 9／9、cleanup-lab 7／7 |
| `strengthen_e2e.py` | 205／205：catalog-apply 28、digests 38、mismatch 22、deep 19、instance 53、keyless 19、retention 16、tampered-json 10；cleanup 34／34 |
| `ui_e2e.mjs all` | 29／29 |
| `schedule_e2e.py all` | 12 個情境第一次就通過；`compat` 第一次在 13／14 中止（見下），重跑 `kit-gate compat cleanup` 20／20、32／32、13／13 |

和 11-17 不同的數字：h7 少 4 項（最新一筆安裝紀錄只更新了套件、計時器原本就在，走的是另一條檢查）；dirs prep 少 2 項（目錄項目已存在，不必再安裝）；compat 多 1 項（要回退的安裝紀錄多一筆）。

`compat` 第一次中止也是執行順序造成的，不是產品問題：`strengthen_e2e.py catalog-apply` 以「應用設定」改了 dev-b 的示範目錄檔，schedule 的 `install` 重新部署時把它改回原本的版本，多了一筆安裝紀錄；`compat` 依序回退時，較早的那筆紀錄發現檔案在安裝後被改過，依設計拒絕覆寫（`Changed since installation: … refusing to overwrite newer work.`）。以 schedule 自己的 `cleanup` 與 `deploy-src.sh b` 恢復後重跑即通過。照這個順序跑時，請先把目錄檔放回原本的版本，或把 schedule 排在 strengthen 之前。另外，`ui_e2e.mjs s2` 拆除 dev-b 時以 `podman rmi -f` 移除 postgres:16-alpine，woowbk-dirs 的資料庫容器（同一個映像）也會一起被移除；之後要跑用到 woowbk-dirs 的情境前，以應用擁有者身分 `systemctl --user start woowbk-dirs-db.service`。

`ui_e2e.mjs` 與 `upload_window.mjs` 需要 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 或 `~/.cache/ms-playwright/chromium-1248`。每個執行器也可只跑單一情境：

| 執行器 | 情境 |
| --- | --- |
| `cli_e2e.py` | `s1` 同機含映像備份、去重與 `busy`、原位還原；`s2` A 下載 → B 上傳、需要金鑰、錯誤金鑰、緊急金鑰、全新部署；`faults` 截斷、翻轉位元組、非備份檔、新版格式、非 root；`s3` 缺映像時預檢失敗；`s2-again`；`f8` 自動回復；`f9` 強制終止還原後以還原前備份恢復；`cancel`；`leaks` |
| `ui_e2e.mjs` | `admin` 需要管理員權限；`s1` 頁面備份、關閉分頁後回到作業、下載核對 SHA-256、原位還原；`s2` 頁面上傳到 dev-b、金鑰步驟、全新部署 |
| `hardening.py` | `h1` 惡意或不一致的備份檔（28 種加 1 個對照組，經真正的上傳流程）；`h2` 空間不足；`h3` 資料庫匯出失敗；`h4` 備份各階段強制終止；`h5` 還原中重新啟動設備；`h6` 約 600 MiB 資料卷的備份、下載、還原與記憶體峰值；`h7` 安裝器回退與重新安裝（含排程備份的計時器：安裝後啟用並執行、回退時停止、停用並移除單元、重新安裝後再啟用）；`sec1` 資料卷與映像封存內植入符號連結（含對照組：證明直接用 podman 匯入時，檔案會被寫到目標以外）；`fidelity` 27 個檔案項目（各種符號連結、硬連結、長檔名與長路徑、非 UTF-8 檔名、FIFO、延伸屬性、setgid／sticky 目錄、不同擁有者）在原位與跨設備還原後的保真度；`fresh` 全新部署遇到同名殘留、被強制終止與程序內回復；`leaks` |
| `schedule_e2e.py` | 排程備份（2026.11.17.1）：`install` 單元與計時器（`systemctl show`／`cat`、verify）；`timer` 由計時器在 5 分鐘整點啟動的真實執行；`fast` 立即到期的時段、兩次啟動只有一個作業、檢查鎖、「排程」標示、備註「排程備份」、journal 每個時段一次；`busy` 先有驗證作業 → 等待 → 之後開始（late）；`timezone` 改連 `/etc/localtime` 後下一次檢查就用新時區；`run-now` 立即執行一次（未儲存、設定檔有問題、去重、busy）；`retention` 排程與手動兩個保留範圍互不影響；`partial` 已停止的應用、不在目錄中的應用；`kit-gate` 沒有金鑰或緊急金鑰未保存時不能開啟（dev-b 實驗室金鑰）；`compat` dev-b 以安裝程式回退到 2026.11.15.2，讀取新檔案與作業紀錄、上傳並還原 dev-a 的排程備份，再回到工作樹；`noise` LogLevelMax=notice 時 PID 1 每次檢查寫的行數；`reboot` 錯過的時段、逾期、開機 10 分鐘內不執行（時間命名空間）、重新開機後補做；`cleanup` |
| `race_probe.py` | 連續執行 110 個短作業，同時不停讀取作業狀態，確認剛結束的作業不會被誤判為「已中斷」，並檢查作業紀錄保留 |
| `dirs_e2e.py` | 主機資料夾示範應用 `woowbk-dirs`（PostgreSQL 16 資料目錄與應用資料都在主機資料夾）：`prep` 前置條件；`d1` 原位還原；`d2` 跨設備全新部署（不同 UID 與 subuid 範圍）；`d3` 對調後失敗的自動回復（直接移回原內容）；`d4` 在解壓、兩次改名之間、對調之後強制終止與復原；`d5` 惡意的資料夾封存；`d6` 全新部署遇到既有非空資料夾；`d7` 資料夾之下有掛載、資料夾本身被 bind mount、其他容器唯讀／可寫入掛載；`leaks`。前置需求見檔案開頭（`deploy-dirs.sh`、`dirs-catalog.sh`、`subids.sh`） |

結果與截圖寫到 `~/.woowbk-lab/evidence/`（`integration/`、`hardening/`、`race/`；每個情境有 `driver.log`、`result.json` 與作業紀錄），不含任何金鑰。執行器只針對示範應用撰寫；其他應用的測試方式見 [app-catalog.md](backup/app-catalog.md)。

2026-11-13 最終回歸（約 1 小時，兩台設備上的已安裝檔案與工作樹逐一比對雜湊，部署後與全部測完後都是 26／26 相同）：

| 執行器 | 結果 |
| --- | --- |
| `cli_e2e.py all` | 126／126：s1 29、s2 22、faults 15、s3 8、s2-again 22、f8 10、f9 9、cancel 6、leaks 5 |
| `ui_e2e.mjs all` | 29／29（admin、s1、s2） |
| `hardening.py all` | 554／554：h1 324、h2 13、h3 28、h4 49、h5 15、h6 12、h7 16、sec1 26、fidelity 21、fresh 43、leaks 7 |
| `race_probe.py a`、`b` | 各 11／11；兩台各 110 個作業，0 個被誤判 |
| 洩漏掃描 | 兩台設備的作業紀錄、日誌、索引與 journal，以及主機上 1144 個證據檔，0 命中 |

2026-11-13 主機資料夾階段（2026.11.13.2，含安全審查 M1–M5、L1–L7 的修正）：`dirs_e2e.py all` 258／258（prep 18、d1 29、d3 18、d4 32、d5 107、d6 11、d7 16、d2 22、leaks 5）；修正後重新部署兩台設備再跑 `cli_e2e.py all` 126／126（s1 29、s2 22、faults 15、s3 8、s2-again 22、f8 10、f9 9、cancel 6、leaks 5）；單元測試主機、測試映像 root（略過 3 項）與 uid 1000 各 613 項通過；頁面 fixture 35／35。掛載點偵測另在參考主機以真實的 tmpfs 與同一檔案系統的 bind mount 實測（資料夾之下、資料夾本身、被取代的舊內容中）：皆被偵測，替換與刪除都被拒絕，掛載的內容完好。`ui_e2e.mjs` 與 `hardening.py` 這一輪沒有重跑。

H8（`upload_window.mjs`）在最終回歸前跑過兩批，每種設定共 6 次，結果見 [backup.md](backup.md) 的「已知限制」，最終回歸沒有重跑。實測時間見 [backup.md](backup.md) 的「實驗室驗證紀錄」。

只有單元測試、未在設備上重現的情況：全新部署在資料匯入剛完成的瞬間被終止、只部分執行的應用在備份時確認核對快照、資料庫執行個體無法列出時的拒絕、索引檔無法讀取時不被覆寫、核對快照在備份期間改變時不保存（例如有新的寫入，或未套用的設定在重新啟動時生效），以及「不建立還原前備份，直接還原」選項。

頁面上的「建立加密金鑰」已於 2026-11-13 在實驗室設備 dev-b 以真正的 Cockpit 362 與已安裝引擎實測：建立後金鑰只顯示一次、緊急金鑰檔含金鑰與編號、未勾選確認不能完成、確認後畫面上不再有金鑰，引擎回報已確認（金鑰檔 root 0600、資料夾 0700）；測完已移除 dev-b 的測試金鑰。此流程尚未納入可重跑的 `ui_e2e.mjs`。dev-a 的金鑰仍是較早由 helper（`key-init`）建立。實驗室中 Cockpit 自身的框架程式在切換管理員權限與換頁時會記錄一個縮寫錯誤（`ne`），開原生「服務」頁也會出現，與備份頁無關。

### HA 匯入（dev-c）

`tests/e2e/lab/ha_import_e2e.py` 在實驗室設備 dev-c（正式主機 Odoo tenant 與 n8n 佇列模式的複本，密鑰全新產生；見 lab README 的 dev-c 一節）上，用為這個功能做的三份真實 HA 備份（加密、未加密、加密未壓縮；金鑰與測試密碼從檔案讀取，從不顯示）走完整流程：上傳 → 檢查作業 → 轉換作業 → 用既有的還原作業匯入 → 在設備內驗證。情境：`baseline`（選用，`--baseline <odoo 備份>,<n8n 備份>`：先還原 dev-c 匯入前的備份）、`upload`、`keys`（沒有金鑰 key-required、錯誤金鑰 wrong-key，檢查與轉換都在作業開始前拒絕）、`check`（三份備份，兩個應用；資料庫 woowtest／woowtest2、聯絡人與附件數、自訂模組 woow_import_probe 要從備份複製或這台已經有、n8n 擁有者、工作流程、憑證、執行紀錄、要修正的工作流程、版本；結束後沒有暫用容器）、`convert`（woowtest＋n8n；`ha_import` 形狀、列表中的 `from_ha` 與備註、`inspect` 預檢全部通過且兩個應用的設定都是 same）、`restore`、`verify`（5 位測試聯絡人、附件 ha-probe.txt 可讀、模組與它的資料、自訂模組資料夾、web.base.url 與升級標記是這台的、odoo.service 啟動即通過升級閘道、四個健康網址 200、Odoo admin 與 ha-probe 能登入、n8n 擁有者能登入、憑證「HA probe header」以 n8n 自己的 `export:credentials --decrypted` 在設備內比對解密值、3 個工作流程且「WOOW 匯入測試 - 排程」啟用、有執行紀錄）、`db2`（未加密備份的 woowtest2，只匯入 Odoo）、`testmode`（加密未壓縮備份、「這只是測試」：Odoo 已 neutralize（只剩 Odoo 自己加的 `invalid` 郵件伺服器）且 database.uuid 換新、n8n 工作流程全部停用，其餘同 verify）、`cleanup`（沒有暫用容器、資料卷、網路、暫存資料夾或金鑰檔）、`leaks`（測試密碼、HA 金鑰與憑證值不在作業紀錄、日誌、索引、`ha-imports.json`、上傳資料夾與設備的 journal 中）。證據寫到 `~/.woowbk-lab/evidence/ha-import/<時間>/`（`run.log`、`results.json`、每個作業的紀錄與日誌，全部遮蔽）。

2026-11-18（feat/ha-import-engine，部署後從匯入前的狀態開始）：74／74 通過，證據 `~/.woowbk-lab/evidence/ha-import/20261118T194230/`。

| 步驟 | 時間 |
| --- | --- |
| 匯入前的狀態（還原 dev-c 基準備份：Odoo、n8n） | 43 秒、113 秒 |
| 檢查作業（兩個應用；加密／未加密／加密未壓縮） | 25／19／15 秒 |
| 轉換 woowtest＋n8n（加密備份，10 MB 的加密備份） | 102 秒 |
| 還原轉換後的備份（含還原前備份、健康檢查） | 155 秒 |
| 轉換 woowtest2（只有 Odoo）／還原 | 48／42 秒 |
| 測試匯入：轉換／還原 | 137／156 秒 |

洩漏掃描 145 個檔案與 5.4 MB 的 journal，0 命中。前一輪（同一天、設備已有先前匯入的自訂模組）68／71：3 項是執行器假設設備是全新的（引擎正確地不再列出要複製的模組），修正執行器後即為上表。開發時在 dev-c 發現並修正：n8n 的 SQLite 複本關閉時把 WAL 寫回主檔（-wal 檔消失）；測試匯入時兩個應用用了同名的暫用網路。

**審查修正（fix/ha-import-review-engine，2026-11-18）** 另加選用情境（都要先 `upload`）：`kill`（轉換在容器步驟中被 SIGKILL：暫用容器活得比作業久，下一次 `status` 的復原把作業標成「轉換 HA 備份的作業意外中斷」並清掉所有暫用容器、資料卷、網路，沒有暫存、金鑰檔、`ha-imports.json` 紀錄或新備份，應用健康）、`cancel`（在新 PostgreSQL 17 的步驟中按取消）、`space`（在 dev-c 裡用大小受限的 tmpfs 蓋住暫存資料夾，主機磁碟從不寫滿：開始前就拒絕、轉換到一半依量到的大小停止，兩次都沒有殘留且應用沒被動到）、`pull`（暫時移除 n8n 的 PostgreSQL 16 標籤：檢查用摘要下載固定的 postgres:16.15-alpine 並用同一個參照執行，之後標回原映像）、`c19`（在這台的 Odoo 叢集用 ALTER SYSTEM 設定 work_mem 與 search_path 清單，轉換沿用兩者、還原後的叢集以它們執行，最後重設）、`rollback`（還原轉換備份時讓資料庫第一次啟動失敗：自動回復到還原前的資料）。`--evidence ha-import-fix` 把證據寫到 `~/.woowbk-lab/evidence/ha-import-fix/<時間>/`。

| 情境 | 結果 |
| --- | --- |
| kill | 4／4，作業在 hapg 步驟被終止，復原後全部清除 |
| cancel | 4／4，取消要求後 13 秒作業結束為「已取消」 |
| space | 7／7：開始前拒絕（需要 10.6 GiB，只有 10.5 GiB）；解開後依量到的叢集大小（134.9 MiB）停止 |
| pull | 3／3，固定摘要即 dev-c 原有的映像；n8n 的映像標回 |
| c19 | 6／6，沿用 search_path、work_mem；還原後 `SHOW` 為 8MB 與 `"$user", public, woowlab` |
| rollback | 4／4，134 秒後「已回復」，還原前寫入的標記仍在 |

同一天以修正後的引擎重跑整個情境（`baseline upload keys check convert restore verify db2 testmode cleanup leaks baseline`）：81／81 通過，證據 `~/.woowbk-lab/evidence/ha-import-fix/20261118T224054/`；檢查 20／24／24 秒、轉換 woowtest＋n8n 103 秒、還原 126 秒、woowtest2 轉換／還原 40／37 秒、測試匯入轉換／還原 114／131 秒；洩漏掃描 287 個檔案與 12.8 MB 的 journal，0 命中。前一次重跑 41／46：n8n 的 SQLite 子程序降成 nobody 後打不開複本（SQLite 以完整路徑開檔，而作業暫存資料夾的上層只有 root 能進入；單元測試不以 root 執行，看不到），改成先 chroot 到複本所在的資料夾再降權後即為上表；那一次也發現執行器在轉換失敗時沿用了先前留下的轉換備份 ID，已修正。結束後 dev-c 還原到匯入前的狀態，並刪除這次測試建立的備份。

第一輪的 `c19` 在執行器自己的 SQL 失敗：執行器把整個 search_path 寫成一個字串常值，PostgreSQL 把它當成「一個」結構描述，Odoo 就找不到 `public` 的資料表（審查 C-06 說的正是這種寫法；`finally` 立即重設，設備沒有受影響）。改成每個元素一個常值後即為上表。

`tests/e2e/lab/ha_import_ui.mjs` 用真正的頁面（dev-c 的 Cockpit，管理員存取）走一次同樣的匯入：「上傳備份檔」（同一個 HA 檔再上傳一次，引擎回覆既有的紀錄，頁面仍開啟 HA 備份頁）→「檢查並匯入…」→ 兩個應用 → 先輸入錯誤金鑰（回到金鑰步驟並顯示引擎的訊息）→ 正確金鑰 → 檢查作業 → 選資料庫、不勾「這只是測試」→ 轉換作業 → 還原精靈（HA 說明、預檢、確認）→ 還原作業 → 結果頁的 HA 提醒，再核對「備份列表」的「HA 備份」「由 HA 轉換」標籤與「活動紀錄」的「檢查 HA 備份」「轉換 HA 備份」。轉換前先執行 `ha_import_e2e.py live`，記錄這台當時的 web.base.url 與升級標記；`--verify` 之後執行 `ha_import_e2e.py verify cleanup leaks`；`--baseline <odoo 備份>,<n8n 備份>` 再還原 dev-c 匯入前的備份（`baseline` 也核對 prodlike_baseline.py 的標記資料列與四個健康網址）。截圖有 1440 與 390 像素寬兩種，頁面的指令碼錯誤必須是 0；HA 金鑰與密碼從不顯示，輸入欄含金鑰時不截圖。證據寫到 `~/.woowbk-lab/evidence/ha-import-ui/<時間>/`。

2026-11-18（feat/ha-import 2569298）：49／49 通過（其中 verify cleanup leaks 15／15），頁面錯誤 0；檢查 29 秒、轉換 125 秒、還原 162 秒；之後 `baseline cleanup` 7／7，資料與匯入前逐項相同。證據 `~/.woowbk-lab/evidence/ha-import-ui/20261118T204850/`。

2026-11-19（最終版本 177c8c6，部署後 36 個已安裝檔案與工作樹 sha256 相同）：50／50 通過（其中 `live` 1／1、`verify cleanup leaks` 15／15），頁面的指令碼與 console 錯誤 0；上傳 6.2 秒、檢查 28.8 秒、轉換 128.3 秒、還原 158.0 秒；之後 `baseline cleanup` 7／7：基準標記資料列都在、匯入的模組、聯絡人與工作流程都不在、四個健康網址 200，沒有暫用容器、資料卷、網路、暫存資料夾或金鑰檔。證據 `~/.woowbk-lab/evidence/ha-import-ui/20261118T231340/`。

尚未實測：多 GB 備份與超過 8 GiB 的單一項目、不同 CPU 架構、兩台實體設備之間的還原（兩台實驗室設備在同一台實體主機上）。正式應用（含沒有 PostgreSQL 的 EMQX、OpenDesign、Headscale，以及使用主機資料夾的 Odoo、Home Assistant、Nextcloud）已在參考主機實測備份與原位還原，見 [production-onboarding.md](backup/production-onboarding.md)；正式應用沒有做跨設備還原。

## 從本機 Cockpit 擷取畫面

瀏覽器驗證需要 Node.js 22+、Playwright Chromium。若已有相容 Chromium，可用 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 指向執行檔，省略下載。

```bash
export COCKPIT_URL='https://your-device.example.com:9090'
export COCKPIT_USER='your-system-user'
read -rsp 'Cockpit password: ' COCKPIT_PASSWORD
export COCKPIT_PASSWORD
npm run capture
unset COCKPIT_PASSWORD
```

可選環境變數：

| 變數 | 用途 |
| --- | --- |
| `COCKPIT_INSECURE=1` | 僅供已確認的自簽測試設備，略過瀏覽器憑證驗證 |
| `COCKPIT_ELEVATE=1` | 在既有授權下切換管理員模式，擷取尚未填密碼的授權視窗 |
| `COCKPIT_PODMAN_OWNER` | 指定容器擁有者選項，需相應管理權限 |
| `COCKPIT_CAPTURE_DIR` | 預設 `.local/screenshots`；保持在 Git 忽略的私人目錄 |
| `PLAYWRIGHT_CHROMIUM_EXECUTABLE` | 指定已安裝 Chromium |

擷取包括登入、12個原生頁面、映像展開、手機登入與完整手機總覽；管理員提示取決於是否請求提升權限及該次登入是否有提示。缺少可選擴充、頁面載入失敗或視覺檢查失敗會記錄失敗並以非零狀態結束。軟體更新頁即使畫面檢查通過，仍不代表套件更新後端可用。

這個工具不刪除映像、不重新啟動服務、不儲存瀏覽器 cookie／登入狀態；截圖仍可能含主機名稱、IP、日誌及帳號，預設不提交至 Git。摘要只記錄版面數值與結果。匯入圖集前由管理者檢視內容：

```bash
sudo python3 scripts/manage.py install --screenshots .local/screenshots
```

重新登入 Cockpit 後開啟「工具 → 畫面參考」。歷史排版前後圖不由 capture 產生；原始研究機已有的圖會保留，新設備會顯示未提供紀錄。


## 登入頁 RWD 驗收

檢查視窗寬度320、360、390、600、601、767、768、769、1024、1440px，特別比較斷點兩側，不能只驗證桌面與手機截圖。標準字級下卡片最大345px，輸入框至少48px高；縮窄視窗不應讓卡片反而變大。登入選項展開、長主機名稱、長錯誤訊息、200%文字及橫放短視窗也須檢查，登入按鈕應可捲動到可視範圍。

2026.11.12.4已對部署主機以Chromium完成上述驗收，摘要見current-state。這些實機登入頁驗證不依賴CI中的Cockpit API fixture，亦不代表CI已連上實際主機。

## 手機導覽列

`tests/mobile-navigation-live.mjs` 是選用的實機瀏覽器測試，需在環境變數提供 `COCKPIT_URL`、`COCKPIT_USER`、`COCKPIT_PASSWORD`，以及必要時 `CHROMIUM_PATH`。它檢查 320–767px 五個按鈕的順序和可點範圍、工具與系統清單分離及搜尋切換、鍵盤、主機／說明／作業階段選單，以及桌面寬度。測試會建立 Cockpit 登入工作階段，但不儲存 Cookie 或操作服務。CI 只檢查語法，不會連接真實主機。
