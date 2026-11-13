# 架構與檔案

```text
瀏覽器 → Cockpit TLS／登入 → Cockpit shell
                            ├─ 原生管理頁（各自 iframe）→ 系統管理後端
                            ├─ woowtechservices → Cockpit 提權 → root helper → 指定使用者 systemd／Podman
                            ├─ woowtechbackup → Cockpit 提權 → root helper woowtech-cockpit-backup
                            │     ├─ 立即回應：狀態、列表、檢視內容、金鑰、上傳／下載資訊
                            │     ├─ 上傳／下載：Cockpit bridge 檔案通道，只限 helper 指定的路徑
                            │     └─ systemd-run 背景作業 → runuser 應用擁有者 → systemd --user／Podman
                            └─ woowtechpreview → 靜態畫面參考
```

## 部署部分

1. `branding/` 安裝到 `/etc/cockpit/branding/`。Cockpit 官方品牌機制讀取這個目錄，登入與 shell 使用品牌 CSS／圖示。字型與 SVG 隨包提供，不依賴 CDN。
2. `preview/` 安裝到 `/usr/local/share/cockpit/woowtechpreview/`。`manifest.json` 的 `tools.index` 註冊「工具 → 畫面參考」。Cockpit 載入此目錄的 HTML、CSS、JS。這是獨立靜態頁，沒有服務控制 API、備份引擎或額外登入系統。
3. 部分原生 iframe 沒有品牌樣式入口。安裝程式只在下列 HTML 的 `</head>` 前補 `../../static/branding.css` 連結：systemd 的 logs、services、hwinfo、terminal，以及 networkmanager 的 firewall。不存在的選用頁會略過；已有連結不重複加入；支援 gzip 版檔案。
4. `services/` 的 HTML／CSS／JS／manifest 安裝到 `/usr/local/share/cockpit/woowtechservices/`；Python helper 獨立安裝到 `/usr/local/libexec/woowtech-cockpit-services`，不放在 Web 套件目錄。設備擁有者設定為 `/etc/woowtech-cockpit/services.json`。此頁負責實際服務狀態、日誌和啟停，使用既有管理員授權。

5. `native/podman/` 提供124版原生頁整合、完整建置來源封存及授權。符合版本時替換原生 `index.js` bundle，使 All 包含已設定擁有者；沿用上游 API、元件及控制。
6. 備份與還原：`backup/` 安裝到 `/usr/local/share/cockpit/woowtechbackup/`（選單「備份與還原」）；`backup-engine/woowbackup/` 安裝到 `/usr/local/lib/woowtech-cockpit-backup/`；入口 `backup-engine/woowtech-cockpit-backup` 安裝為 `/usr/local/libexec/woowtech-cockpit-backup`（root 0755，`#!/usr/bin/python3 -I`）。受信任應用目錄為 `/etc/woowtech-cockpit/backup/apps/`，預設是空的；全新部署用的範本在 `/usr/local/share/woowtech-cockpit-backup/catalog/`。執行資料（備份檔、金鑰、作業）由引擎建立，安裝器不管理。使用方式見 [backup.md](backup.md)。

Cockpit 套件升級可能覆寫第三及第五部分；重新執行安裝可針對升級後的新檔案補連結。CSS 使用 PatternFly 6 類別；Cockpit 改版後需要重測，不能保證所有未來版本自動相容。

手機版底部的「工具」快捷鍵由 `branding/mobile-navigation.js` 增加，使用原生側邊欄；手機按「系統」只顯示系統群組，按「工具」只顯示工具群組，切換時清除前一群組的搜尋條件。桌面仍顯示所有群組。安裝器只在原生 shell 的 `index.html` 插入本機腳本連結；上游套件更新後可能需要重新執行安裝並驗證 DOM 與鍵盤操作。當上游結構不同時腳本不啟用，原生導覽仍可使用。

## 備份與還原元件

| 元件 | 位置 | 職責 |
| --- | --- | --- |
| Cockpit 頁面 | `backup/`（`backup.js`） | 只用 DOM 建立畫面；每個動作以 `cockpit.spawn` 執行固定的 helper 指令（`superuser: "require"`），請求 JSON 經標準輸入送出；作業進行中每 1.5 秒查詢進度；上傳用 `fsreplace1` 通道（512 KiB 分段、最多 4 MiB 未確認），下載用 `fsread1` 通道 |
| root helper | `backup-engine/woowtech-cockpit-backup` | 非 root 拒絕執行；載入前確認引擎目錄與每個模組都是 root 擁有、群組與其他人不可寫入；以 `python3 -I` 執行，不受 Python 相關環境變數影響，也不讀寫位元組碼快取；標準輸出只有一個 JSON 物件 |
| 指令介面 | `woowbackup/cli.py` | 嚴格驗證請求（型別、長度、列舉、格式，拒絕未知欄位，最大 1 MiB），分派指令，錯誤以穩定代碼與中文訊息回應 |
| 格式與加密 | `archive.py`、`keys.py`、`storage.py`、`util.py` | `.woowbackup` 讀寫與完整驗證、age X25519 金鑰與緊急金鑰、本機備份、上傳與暫存區 |
| 巢狀 tar | `nested.py` | 備份內資料卷與映像封存的完整檢查，以及交給 Podman 的乾淨 tar 重新產生 |
| 應用目錄 | `catalog.py` | 只載入 root 擁有、不可被他人寫入、非符號連結的目錄項目，逐欄嚴格驗證 |
| 擁有者執行器 | `podman.py` | 以 `runuser -u <擁有者> -- env -i …` 執行固定指令；擁有者家目錄內的檔案存取也以擁有者身分、逐層不跟隨符號連結進行 |
| 轉接器 | `adapters/quadlet_postgres.py` | 偵測部署、預檢、暫停寫入服務並匯出、還原、健康檢查、資料核對、全新部署失敗時的移除 |
| 流程與作業 | `flows.py`、`jobs.py` | 備份／還原／驗證流程、還原前備份與自動回復；`systemd-run` 背景作業、引擎鎖、作業紀錄（保留最近 200 筆已結束的作業）、去重、取消與中斷復原 |
| 示範應用 | `catalog-examples/woowbk-demo/` | 實驗室專用的受信任目錄項目、Quadlet 範本與測試應用 |

一次作業：頁面呼叫 `backup-start`、`restore-start` 或 `verify-start` → helper 驗證並寫入作業紀錄 → `systemd-run --unit=woowtech-backup-<作業 ID>.service … run-job <作業 ID>`（單元另設記憶體與工作數上限）後立即回應 → 背景程序取得 `/run/woowtech-backup/engine.lock` 的獨占鎖，每次階段或進度改變都以原子方式更新 `/var/lib/woowtech-backup/jobs/<作業 ID>.json` → 頁面以 `job-status` 讀取。作業不依賴瀏覽器連線；程序消失而紀錄仍在執行中時，下次讀取狀態會標為已中斷，從不自動重做。

## 備份與還原的信任邊界

1. **瀏覽器與頁面不受信任。** 頁面隱藏按鈕不代表授權：helper 需要 root（Cockpit 管理員存取），並逐欄驗證每個請求。任何能取得 Cockpit 管理員權限的帳號都能管理所有應用的備份；管理員之間沒有分權。
2. **helper 與引擎程式。** helper 只從安裝後 root 擁有、群組與其他人不可寫入的目錄載入引擎，不直接執行 repository checkout 中的程式；安裝器若發現上層資料夾不安全會拒絕安裝。安裝器複製的是執行當下 checkout 的內容，請從可信、一般帳號無法修改的 checkout 安裝。
3. **root 與應用擁有者。** 對應用的所有操作都以擁有者身分、固定參數與乾淨環境執行，不使用 shell；名稱都先經格式驗證。root 不直接開啟擁有者家目錄內的路徑。
4. **本機目錄與備份檔。** 本機目錄項目與範本由 root 擁有，是還原時寫入內容的唯一依據；備份檔只提供目錄已宣告項目的內容。上傳的備份檔在檔頭、age 認證、zstd 與每個項目的名稱、類型、大小與 SHA-256 都通過前一律視為不可信，只能解開到 root 0700 的空暫存資料夾，拒絕連結、裝置檔、路徑穿越、重複、多出或缺少的項目，並限制項目數（4000）、清單大小（1 MiB）與總量。備份中的資料卷與映像封存在還原作業的相容性檢查階段（建立還原前備份與任何變更之前）完整檢查，再由引擎重新產生乾淨的 tar 餵給 Podman，避免 Podman 解開時跟隨封存內的符號連結（實驗室實測 Podman 4.9.3 會跟隨）；建立備份時也以同樣規則檢查每個資料卷匯出。「驗證」作業只檢查外層封存。備份檔不能攜帶程式；轉接器屬於引擎，備份檔中的 Quadlet 檔從不安裝；設定檔只能寫到應用自己的設定目錄。
5. **金鑰。** 設備金鑰與匯入的金鑰存在 `/etc/woowtech-cockpit/backup/keys/`（0700，檔案 0600）。使用者提供的金鑰只經標準輸入的 `key` 欄位傳遞，從不出現在命令列參數、環境變數、作業紀錄、日誌或錯誤訊息；單次作業的暫時金鑰放在 `/run/woowtech-backup/`（記憶體檔案系統），作業結束即刪除。
6. **上傳與下載路徑。** 上傳只能寫入 helper 產生的 `uploads/<上傳 ID>.part`，完成時拒絕符號連結、非一般檔案與大小不符；下載只回傳 `archives/` 內的備份檔路徑。
7. **明文暫存。** 作業期間的資料庫匯出、資料卷內容與密鑰以明文存在 `/var/lib/woowtech-backup/staging/<作業 ID>/`（root 0700），作業結束或判定中斷時刪除；刪除後的資料區塊可能殘留在磁碟上，這是已知的殘留風險，見 [backup.md](backup.md) 的安全須知。

完整規格見 [backup/CONTRACT.md](backup/CONTRACT.md)。

## 原始碼索引

| 路徑 | 用途 |
| --- | --- |
| `branding/branding.css` | 與參考主機相同的現行白底品牌與排版樣式 |
| `branding/assets/` | 官方 SVG 標誌 |
| `branding/fonts/` | 本地 webfont 與授權文字 |
| `preview/` | 圖集、缺圖處理、歷史排版說明 |
| `native/podman/` | 原生124版整合、來源封存、修補、建置產物及授權 |
| `scripts/build-podman.sh` | 從封存及 lockfile 重建原生 JS |
| `services/` | 實際服務管理頁及受控管理 helper |
| `backup/` | 「備份與還原」Cockpit 頁面 |
| `backup-engine/` | 備份引擎 `woowbackup/` 與 root helper 入口 |
| `catalog-examples/woowbk-demo/` | 實驗室示範應用的目錄項目、Quadlet 範本與工具 |
| `scripts/manage.py` | 安裝、SHA-256 檢查及回退 |
| `scripts/bootstrap-ubuntu.sh` | Ubuntu backports 套件與備份工具（age、zstd）安裝 |
| `scripts/capture.mjs` | 使用環境變數登入目標主機、擷取本機畫面 |
| `tests/` | 暫存根目錄交易測試、備份引擎單元測試、圖集／服務／備份頁瀏覽器測試 |
| `tests/e2e/lab/` | 實驗室設備工具與備份還原端到端測試 |
| `examples/` | 可選反向代理設定範例 |
| `docs/` | 現況、部署、維護與驗證限制；`docs/backup/` 為備份還原的規格與應用接入文件 |

狀態檔位於 `/var/lib/woowtech-cockpit/installed.json`；安裝交易與原檔備份位於 `/var/backups/woowtech-cockpit-source/<backup_id>/`。這是介面安裝的交易備份，與「備份與還原」的應用備份（`/var/lib/woowtech-backup/`）無關。畫面參考套件不會讀取這些管理檔案。

品牌目錄可能在未登入時被瀏覽器讀取，只可放公開素材。帳密、憑證私鑰、PAM、客戶資料、原始主機日誌和實機截圖不隨此 Git repository 發布。每台設備的截圖只在管理者明確匯入後才顯示。

官方機制：[Branding](https://github.com/cockpit-project/cockpit/blob/main/doc/branding.md)、[Cockpit 362 packages](https://docs.cockpit-project.org/cockpit-guide/362/guide/packages.html)。本專案沿用套件預設 CSP，JS／CSS 都是獨立本地檔案。
