# 驗證與截圖

## 自動測試

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_source.py
bash -n scripts/bootstrap-ubuntu.sh scripts/build-podman.sh
node --check scripts/capture.mjs
npm ci
npx playwright-core install chromium
npm test
```

`unittest` 在暫存根目錄檢查安裝、重複安裝、純 HTML／gzip 原生入口、檔案與權限還原、保留客戶檔、上游升級後重新套用、拒絕舊回退、symlink 防護、寫入失敗回復、損壞備份與舊版拒絕。不需要 sudo，不會碰本機 Cockpit。

瀏覽器測試將來源安裝到另一個暫存根目錄，以限制 CSP 提供本機靜態服務，檢查1440／1024／390／360px的全白圖集、缺圖提示、完整圖連結、SVG圖示及無橫向溢出，再驗證加入一張本機圖片。CI執行同一組測試，不需主機密碼。

CI 不部署真實 Ubuntu 服務、不登入參考主機、不測試完整災難復原。參考主機的真實驗證範圍見 current-state。

## 服務管理測試

`tests/test_services.py` 以模擬指令結果驗證權限、固定指令參數、使用者身分、日誌範圍、輸出過濾、停止中的 Quadlet、錯誤／逾時、並行鎖定及失敗狀態。未命名模板會讓 systemctl 的批次 show 提前結束，因此有專門的回歸案例，避免後方服務被漏列。含安裝器共22項 Python 測試。

`tests/services-ui.mjs` 提供本機 Cockpit API fixture，測試9個行為：未授權資料隔離、停止服務與分頁、確認／取消、stdout錯誤、關鍵服務保護、日誌文字安全、擁有者導覽、桌面／手機版面，以及斷線後重新連線而不重送操作。它不執行真實主機操作；與圖集測試同由 `npm test` 執行。

`tests/managed-owners.mjs` 另以原生 Application 的事件介面驗證4個問題：All 自動載入、首次指定 UID、提升權限後載入，以及舊連線不得清掉新連線。安裝器另測試124版套用、125版保留原生檔案，以及 JS 備份／回退。完整原生建置可執行 `bash scripts/build-podman.sh`；需要 npm 下載鎖定版本的建置依賴。

真實驗證另使用三個獨立測試單元：一般使用者服務、使用者 Quadlet，以及系統服務。從已登入的 Cockpit 頁面點擊啟動／重新啟動／停止，再由 systemd 狀態及實際 PID 交叉確認；Quadlet 另確認停止後容器移除但服務仍可再啟動。驗證完成後移除測試單元與容器，不對正式應用進行停機測試。

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
