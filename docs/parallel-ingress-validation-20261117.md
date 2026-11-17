# Apporo 雙入口收尾驗收 — 2026-11-17

本次將先前本機 Apporo 範例入口收斂為 [parallel-ingress](../parallel-ingress/README.md) 的可重現部署。主入口仍為 WOOW，兩個入口共用同一台主機、服務管理、備份與 Pi；不建立第二組應用資料或服務。

## 已修正

| 原問題 | 結果 |
| --- | --- |
| Apporo 備份頁落後共用 main | 從同一份固定來源產生備份頁，實際載入排程設定、保留份數、既有執行紀錄；不更動設備的排程 |
| Pi 使用 WOOW-only 公開閘道而 403 | 為精確 public／loopback origin 建立兩個独立 gateway，保留 Cockpit 與 Pi 各自登入；不偽造瀏覽器 Origin |
| 畫面參考 404 | 安裝完整套件與素材；17 個尚未提供的設備截圖明確顯示待擷取，不請求缺少的圖片 |
| 雙入口只存在本機樣板 | 已有 config 範例、固定映像 digest、installer、來源／檔案 receipt、驗證與回退；Ubuntu 發行材料會釘選此共同來源 |
| favicon、深色字型與 Pi 外框殘留 | 合入協作對話的品牌修正，涵蓋 Cockpit 實際 icon 路徑、圖示快取版本、登入標題、PatternFly 深色字型與 Pi 外框 |

## 實機驗證

- 安裝產生 94 個受 receipt 管理的檔案；25 個共同後端檔案逐一核對雜湊與完整 Python 模組清單。
- Apporo 使用 Cockpit 登入並提權後，可讀到 13 個應用卡片、主機與 rootless 管理範圍、服務／容器狀態，備份總覽與排程頁載入實際資料。
- Pi 保留獨立密碼登入，新增對話確實收到助理角色產生的回覆；回覆出現在網頁，SSE 事件串流正常。
- Pi 在手機尺寸下沒有橫向溢位；Cockpit 深淺色會同步至 Pi，Apporo 主色來自品牌 profile，不改原生 Pi 的獨立偏好。
- 新 public origin 在本機模擬可信 HTTPS proxy 後，可建立 Cockpit session，WebSocket 升級 101，登入後 Pi／備份／參考頁 200。匿名請求 401、錯誤 Origin 403。
- 原 WOOW 對外入口另以瀏覽器完成 Cockpit／Pi 登入、手機及主題回歸。
- Apporo 使用真實原生後端的畫面驗收不改排程，不停止應用；此次沒有重做正式應用資料的備份還原演練。兩品牌備份 UI 的完整情境由既有瀏覽器測試覆蓋。
- 雙品牌 PWA fixture 均完成瀏覽器安裝、獨立視窗啟動。實機 Apporo manifest、圖示與入口另行核對；不把 fixture 說成外網驗收。

## 回退與協作衝突

實機曾發現另一個協作對話同時把 Quadlet 指向使用者目錄中的修改副本。這會造成 root receipt 與真實 frontend 不一致；已協調停止重複部署、保留品牌修正，並增加更新前、產生檔案後以及 rollback snapshot 的一致性檢查。受管理入口若已被其他程序修改，installer 現在會在切換前拒絕，不覆蓋差異。

在收斂後的實機上已完成：新版安裝 → 回退前版 → 前版 verify 通過 → 再安裝新版 → 新版 verify 通過。暫存的第三個 Pi gateway 已停用並封存；目前僅由正式 public／loopback units 接管。回退只涉及入口設定，不涉及客戶應用資料。

回歸測試另覆蓋失敗部署、舊服務開關狀態、rootless owner 寫入 Quadlet、嚴格 umask、root-owned 設定與 Node 祖先、來源異動、額外模組、不可讀素材、鎖定及不相容前版拒絕。

## 對外網址界線

協作對話已將原先借用的 `cfgui` 網址還給 Cloudflare 管理介面並保留原有 Access。Apporo 現行部署使用獨立的預定 public origin，且停用舊 `18000` 相容 listener；新路由的 PaaS 訂閱／外網開通由該對話另外處理。此驗收不代表該新網域已正式開通，也未修改 Cloudflare Access、DNS 或訂閱。

本機入口為安裝 config 的 `listen_port`，僅監聽 loopback。遠端可依安裝文件使用 SSH 轉送。沒有將此除錯入口直接公開到 LAN／VPN。

## 可重現驗證

- `python3 -m unittest discover -s tests -t . -v`
- `python3 scripts/check_source.py`
- `node --test pi-web-integration/tests/*.mjs`
- `node tests/brand-browser.mjs`（兩品牌各 79 個備份 UI 情境，以及應用、服務和主題）
- `node tests/pwa-brands.mjs`
- `node tests/parallel-ingress-live.mjs`（opt-in、環境變數提供憑證）
- `node tests/pi-web-public-live.mjs`（opt-in；只有明確設 `PI_WEB_CHAT_TEST=1` 才新增對話）

原始含主機資料的畫面與測試日誌保存在本機私有驗收目錄，未推送帳密、Token、Cookie、對話內容或客戶資料。
