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

`tests/test_services.py` 以模擬指令結果驗證權限、固定指令參數、使用者身分、日誌範圍、輸出過濾、停止中的 Quadlet、錯誤／逾時、並行鎖定及失敗狀態。未命名模板會讓 systemctl 的批次 show 提前結束，因此有專門的回歸案例，避免後方服務被漏列。含安裝器共22項 Python 測試。

`tests/services-ui.mjs` 提供本機 Cockpit API fixture，測試9個行為：未授權資料隔離、停止服務與分頁、確認／取消、stdout錯誤、關鍵服務保護、日誌文字安全、擁有者導覽、桌面／手機版面，以及斷線後重新連線而不重送操作。它不執行真實主機操作；與圖集測試同由 `npm test` 執行。

`tests/managed-owners.mjs` 另以原生 Application 的事件介面驗證4個問題：All 自動載入、首次指定 UID、提升權限後載入，以及舊連線不得清掉新連線。安裝器另測試124版套用、125版保留原生檔案，以及 JS 備份／回退。完整原生建置可執行 `bash scripts/build-podman.sh`；需要 npm 下載鎖定版本的建置依賴。

真實驗證另使用三個獨立測試單元：一般使用者服務、使用者 Quadlet，以及系統服務。從已登入的 Cockpit 頁面點擊啟動／重新啟動／停止，再由 systemd 狀態及實際 PID 交叉確認；Quadlet 另確認停止後容器移除但服務仍可再啟動。驗證完成後移除測試單元與容器，不對正式應用進行停機測試。

## 備份與還原測試

分三層：不需設備的單元與來源檢查、頁面 fixture 瀏覽器測試，以及兩台隔離實驗室設備上的端到端測試。**所有備份還原測試都不得在正式主機或正式應用上執行。**

### 單元測試與來源檢查

`tests/backup/` 涵蓋封存格式與惡意封存檔、金鑰、本機儲存、應用目錄驗證、以擁有者身分執行指令、`quadlet-postgres` 轉接器、備份／還原／驗證流程、背景作業與中斷復原，以及 helper 的 JSON 介面；外部指令以假的執行器模擬。`tests/test_manage.py` 檢查備份套件的安裝，`tests/e2e/test_demo_fixture.py` 離線檢查示範應用。這些都包含在上方的 `unittest` 指令中。

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

2026-11-13 整合輪紀錄：主機 317 項通過、50 項因沒有 age 略過；測試映像以 root 執行 317 項通過、3 項略過（只適用非 root），以 uid 1000 執行 317 項通過、0 項略過。最終數字：驗證結果待回歸測試更新。

### 頁面 fixture 測試

`tests/backup-ui.mjs`（包含在 `npm test`）以假的 `window.cockpit` 記錄每次 helper 呼叫並模擬上傳與下載通道，不會啟動任何程序。測試金鑰設定與緊急金鑰、建立備份與下載、64 KiB 分段與 2 MiB 確認視窗的上傳與取消、需要金鑰的上傳還原、自動回復結果、重新載入後回到作業與中斷指引、`busy`、需要管理員權限、空目錄、刪除與取消的確認、驗證要求金鑰、惡意字串只以文字顯示、1440／1024／768／390／360／320px 版面、鍵盤焦點、斷線與 helper 缺失、下載失敗，以及原始碼規則（只用 DOM 建立內容、固定 helper、金鑰只在標準輸入的 `key` 欄位、無遠端資源）。整合輪紀錄 18／18 通過。

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
python3 -I tests/e2e/lab/hardening.py all                    # 強化測試 H1–H7 與洩漏檢查
node tests/e2e/lab/upload_window.mjs                         # H8：較大上傳視窗的評估（只在測試瀏覽器內修改）
```

`ui_e2e.mjs` 與 `upload_window.mjs` 需要 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 或 `~/.cache/ms-playwright/chromium-1248`。每個執行器也可只跑單一情境：

| 執行器 | 情境 |
| --- | --- |
| `cli_e2e.py` | `s1` 同機含映像備份、去重與 `busy`、原位還原；`s2` A 下載 → B 上傳、需要金鑰、錯誤金鑰、緊急金鑰、全新部署；`faults` 截斷、翻轉位元組、非備份檔、新版格式、非 root；`s3` 缺映像時預檢失敗；`s2-again`；`f8` 自動回復；`f9` 強制終止還原後以還原前備份恢復；`cancel`；`leaks` |
| `ui_e2e.mjs` | `admin` 需要管理員權限；`s1` 頁面備份、關閉分頁後回到作業、下載核對 SHA-256、原位還原；`s2` 頁面上傳到 dev-b、金鑰步驟、全新部署 |
| `hardening.py` | `h1` 26 種惡意封存檔；`h2` 空間不足；`h3` 資料庫匯出失敗；`h4` 備份各階段強制終止；`h5` 還原中重新啟動設備；`h6` 約 600 MiB 資料卷的記憶體峰值；`h7` 安裝器回退與重新安裝；`leaks` |

結果與截圖寫到 `~/.woowbk-lab/evidence/integration/` 與 `~/.woowbk-lab/evidence/hardening/`（`driver.log`、`result.json`、作業紀錄），不含任何金鑰。執行器只針對示範應用撰寫；其他應用的測試方式見 [app-catalog.md](backup/app-catalog.md)。

2026-11-13 整合輪：CLI 端到端各情境全部通過（s1 29／29、s2 22／22、faults 15／15、s3 8／8、s2-again 22／22、f8 9／9、f9 9／9、cancel 6／6、leaks 5／5），頁面端到端 28／28（跑兩輪皆通過）；實測時間見 [backup.md](backup.md)。強化測試 H1–H8 與最終回歸：驗證結果待回歸測試更新。

尚未實測：多 GB 備份與超過 8 GiB 的單一項目、不同 CPU 架構。

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
