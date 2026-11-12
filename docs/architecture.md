# 架構與檔案

```text
瀏覽器 → Cockpit TLS／登入 → Cockpit shell
                            ├─ 原生管理頁（各自 iframe）→ 系統管理後端
                            ├─ woowtechservices → Cockpit 提權 → root helper → 指定使用者 systemd／Podman
                            └─ woowtechpreview → 靜態畫面參考
```

## 部署部分

1. `branding/` 安裝到 `/etc/cockpit/branding/`。Cockpit 官方品牌機制讀取這個目錄，登入與 shell 使用品牌 CSS／圖示。字型與 SVG 隨包提供，不依賴 CDN。
2. `preview/` 安裝到 `/usr/local/share/cockpit/woowtechpreview/`。`manifest.json` 的 `tools.index` 註冊「工具 → 畫面參考」。Cockpit 載入此目錄的 HTML、CSS、JS。這是獨立靜態頁，沒有服務控制 API、備份引擎或額外登入系統。
3. 部分原生 iframe 沒有品牌樣式入口。安裝程式只在下列 HTML 的 `</head>` 前補 `../../static/branding.css` 連結：systemd 的 logs、services、hwinfo、terminal，以及 networkmanager 的 firewall。不存在的選用頁會略過；已有連結不重複加入；支援 gzip 版檔案。
4. `services/` 的 HTML／CSS／JS／manifest 安裝到 `/usr/local/share/cockpit/woowtechservices/`；Python helper 獨立安裝到 `/usr/local/libexec/woowtech-cockpit-services`，不放在 Web 套件目錄。設備擁有者設定為 `/etc/woowtech-cockpit/services.json`。此頁負責實際服務狀態、日誌和啟停，使用既有管理員授權。

Cockpit 套件升級可能覆寫第三部分；重新執行安裝可針對升級後的新檔案補連結。CSS 使用 PatternFly 6 類別；Cockpit 改版後需要重測，不能保證所有未來版本自動相容。

## 原始碼索引

| 路徑 | 用途 |
| --- | --- |
| `branding/branding.css` | 與參考主機相同的現行白底品牌與排版樣式 |
| `branding/assets/` | 官方 SVG 標誌 |
| `branding/fonts/` | 本地 webfont 與授權文字 |
| `preview/` | 圖集、缺圖處理、歷史排版說明 |
| `services/` | 實際服務管理頁及受控管理 helper |
| `scripts/manage.py` | 安裝、SHA-256 檢查及回退 |
| `scripts/bootstrap-ubuntu.sh` | Ubuntu backports 套件安裝 |
| `scripts/capture.mjs` | 使用環境變數登入目標主機、擷取本機畫面 |
| `tests/` | 暫存根目錄交易測試、圖集瀏覽器測試 |
| `examples/` | 可選反向代理設定範例 |
| `docs/` | 現況、部署、維護與驗證限制 |

狀態檔位於 `/var/lib/woowtech-cockpit/installed.json`；安裝交易與原檔備份位於 `/var/backups/woowtech-cockpit-source/<backup_id>/`。畫面參考套件不會讀取這些管理檔案。

品牌目錄可能在未登入時被瀏覽器讀取，只可放公開素材。帳密、憑證私鑰、PAM、客戶資料、原始主機日誌和實機截圖不隨此 Git repository 發布。每台設備的截圖只在管理者明確匯入後才顯示。

官方機制：[Branding](https://github.com/cockpit-project/cockpit/blob/main/doc/branding.md)、[Cockpit 362 packages](https://docs.cockpit-project.org/cockpit-guide/362/guide/packages.html)。本專案沿用套件預設 CSP，JS／CSS 都是獨立本地檔案。
