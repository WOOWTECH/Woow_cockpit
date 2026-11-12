# 服務管理

入口：Cockpit「系統 → 服務管理」，路徑 `/woowtechservices`。使用既有 Linux 帳號登入，再透過 Cockpit 頂端的管理員存取功能授權。

## 能做什麼

- 在「管理範圍」選擇本機系統，或安裝時設定的 rootless 服務擁有者。
- 查看啟用／未啟用／失敗狀態、服務類型、關聯容器、服務來源與最近100筆日誌。
- 依名稱、描述、映像、狀態及類型搜尋，每頁最多40筆。
- 啟動、停止、重新啟動一個既有 systemd 服務；確認視窗會再讀取狀態並顯示目標服務與管理範圍。
- 查看 Podman 容器、映像、狀態與連接埠；有 `PODMAN_SYSTEMD_UNIT` 的容器可管理其對應服務。
- 原生 Podman 連結帶入擁有者 UID；進入後仍需確認 Show 選項。沒有 systemd 關聯的一般容器沿用該頁的原生操作。

Quadlet 的操作執行 `systemctl --user start/stop/restart`，保留既有單元相依與重啟規則。停止 Quadlet 後容器可能被移除，但服務仍會列在清單，可再次啟動。此頁不執行映像升版、卷刪除或容器重建設定。

## 設定服務擁有者

```bash
sudo python3 scripts/manage.py install --service-owner <服務帳號>
# 多個服務帳號可重複指定；提供參數時會取代已設定的完整帳號清單
sudo python3 scripts/manage.py install --service-owner <帳號一> --service-owner <帳號二>
# 更新來源並保留現行帳號設定
sudo python3 scripts/manage.py install
```

設定存於 root 擁有、0600權限的 `/etc/woowtech-cockpit/services.json`，格式為 `{"owners":["operator"]}`。Root 服務固定使用「本機系統」範圍，不放進 owners。來源沒有內建任何主機帳號或密碼。

若不指定且設備原先沒有設定，僅提供本機系統範圍。使用者服務管理器必須已啟動；需要登出後持續運作的設備，依 deployment.md 設定 linger。安裝器不擅自啟動所有應用。

## 為何新增獨立頁面

在參考版本 Cockpit362／cockpit-podman124：

| 原生頁面 | 跨使用者限制 |
| --- | --- |
| Services 的 User 範圍 | 指的是目前登入者，提升管理權限不會切換成應用擁有者 |
| Podman 的 All | 合併系統與目前登入者，沒有合併所有使用者 |
| Podman 其他使用者選單 | 從運行中容器發現擁有者；只有停止容器的使用者可能不出現 |
| 其他使用者的 Quadlet | 原生頁刻意限制停止／重啟，未完整探索其停止中的生成服務 |

因此管理頁直接在已設定擁有者的身分下查詢其 systemd。它同時讀取已載入服務與 unit files，再取得狀態，避免只看運行中容器而漏掉可啟動的服務。未命名的 `foo@.service` 模板不是可運行的實例，不列入操作清單。

原生頁的擁有者導覽為 `/podman#/?owner=<UID>`。本頁只在系統範圍提供原生 Services 服務連結，避免把其他使用者的單元錯連到登入者範圍。

### 原生 Podman 首次載入限制

124版會在其他使用者的發現完成前處理網址，有機會把指定 UID 改回 `All`。實機也觀察到選中正確 UID 後清單仍未載入；直接查詢相同 socket 的 API 有容器。實測解法是在原生頁將 Show 切到 `All`，再選回服務擁有者。`All` 空白不代表其他帳號沒有容器。

曾試用官方 manifest preload 機制，但無法保證權限切換及首次載入都正確，已撤除。此版本沒有修改上游 Podman 程式，也不宣稱修好其載入問題。跨使用者 Quadlet 的日常管理使用本專案「服務管理」；它直接讀取選定帳號，沒有依賴上述原生頁的探索狀態。

上游依據：[Podman124 擁有者選擇](https://github.com/cockpit-project/cockpit-podman/blob/124/src/ContainerHeader.jsx)、[其他使用者 Quadlet 控制限制](https://github.com/cockpit-project/cockpit-podman/blob/124/src/Containers.jsx)、[Cockpit362 Services](https://github.com/cockpit-project/cockpit/blob/362/pkg/systemd/services.jsx)。

## 權限與執行

靜態頁透過正式 `cockpit.spawn(..., {superuser: "require"})` API 呼叫 `/usr/local/libexec/woowtech-cockpit-services`。Helper 是複製到系統目錄的 root 檔案，不是指向使用者工作目錄的 symlink。Python 使用 isolated mode；下層指令使用固定執行檔、參數陣列與受控環境，不接受 shell 字串。

處理使用者服務時，helper 以 `runuser` 切換實際 UID，再設定該使用者的 runtime／D-Bus 位置。只設定環境變數不會改變執行身分，因此不能代替此步驟。

此功能給已獲管理員權限的操作者使用，沒有新增免密 sudo、共用 socket 權限或額外 Web API。未授權時不提供跨使用者資料。狀態輸出不包含容器環境變數、密鑰、mount資料或啟動命令。日誌是管理者有權讀取的服務日誌，仍可能含應用寫入的敏感內容，請勿直接公開。

同一服務的狀態操作會鎖定並等待 systemd 指令完成；逾時顯示結果未確認，需要重新整理。操作目標及結果寫入 journal 的 `woowtech-cockpit-services` tag，沒有記錄密碼。認證與登入紀錄由 Cockpit／系統負責。頁面顯示的是單元狀態；active 不代表應用業務功能或所有健康檢查通過。

## 邊界

- 只管理已註冊的 systemd 服務；任意終端或桌面程式不會自動變成服務。
- 不提供整組應用的升版、備份還原、複合啟停順序或新服務安裝。
- 保留原有 `[Install]`、timer和開機設定；不對生成的 Quadlet 執行 `systemctl enable`。
- Cockpit、D-Bus、登入與使用者管理器等會中斷管理連線的關鍵單元，須從本機維護終端處理。
- 「本機自訂」分類依 unit 檔案來源判定；系統套件提供的原生服務仍可從系統範圍找到。
- 原生 Podman 的擁有者發現限制仍存在；跨使用者 Quadlet 應使用本頁。需要原生頁管理只有停止容器的帳號時，可直接用該帳號登入。

回退會還原此套件、helper及設定檔；不會回復操作者先前透過頁面執行的服務啟停。`--no-services` 僅停止管理套件檔案，不是解除安裝或撤銷既有服務操作。
