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

`ui_e2e.mjs` 與 `upload_window.mjs` 需要 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 或 `~/.cache/ms-playwright/chromium-1248`。每個執行器也可只跑單一情境：

| 執行器 | 情境 |
| --- | --- |
| `cli_e2e.py` | `s1` 同機含映像備份、去重與 `busy`、原位還原；`s2` A 下載 → B 上傳、需要金鑰、錯誤金鑰、緊急金鑰、全新部署；`faults` 截斷、翻轉位元組、非備份檔、新版格式、非 root；`s3` 缺映像時預檢失敗；`s2-again`；`f8` 自動回復；`f9` 強制終止還原後以還原前備份恢復；`cancel`；`leaks` |
| `ui_e2e.mjs` | `admin` 需要管理員權限；`s1` 頁面備份、關閉分頁後回到作業、下載核對 SHA-256、原位還原；`s2` 頁面上傳到 dev-b、金鑰步驟、全新部署 |
| `hardening.py` | `h1` 惡意或不一致的備份檔（28 種加 1 個對照組，經真正的上傳流程）；`h2` 空間不足；`h3` 資料庫匯出失敗；`h4` 備份各階段強制終止；`h5` 還原中重新啟動設備；`h6` 約 600 MiB 資料卷的備份、下載、還原與記憶體峰值；`h7` 安裝器回退與重新安裝；`sec1` 資料卷與映像封存內植入符號連結（含對照組：證明直接用 podman 匯入時，檔案會被寫到目標以外）；`fidelity` 27 個檔案項目（各種符號連結、硬連結、長檔名與長路徑、非 UTF-8 檔名、FIFO、延伸屬性、setgid／sticky 目錄、不同擁有者）在原位與跨設備還原後的保真度；`fresh` 全新部署遇到同名殘留、被強制終止與程序內回復；`leaks` |
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
