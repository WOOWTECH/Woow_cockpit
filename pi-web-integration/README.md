# Cockpit Pi Web 側邊欄

Cockpit 362 的獨立 package 與 gateway，從側邊欄開啟主機既有的 Pi Web。使用者需要先登入 Cockpit，再以 Pi Web 自己的密碼登入；當 Pi Web 密碼保護未啟用或無法確認時 gateway 拒絕代理。Pi Web 原始資料、設定與服務都沿用。

## 網路方式

本機區網與 VPN 入口均使用 HTTP。VPN 流量是否加密取決於 VPN；區網 HTTP 本身不加密。各 gateway 只綁定安裝時指定的 IP。另可設定一個明確的對外 HTTPS origin，由本專案的 PWA gateway 在同網域代理 Pi Web；公開用的 Pi gateway 僅監聽 loopback，不直接公開 LAN HTTP gateway。

HTTP 非安全瀏覽器環境可能限制剪貼簿、service worker 及其他只在安全環境提供的網頁功能；實際能力取決於瀏覽器及 Pi Web 功能。Pi Web 中限制在 localhost 的 OS 本機操作也可能不可用。

## 安裝

需要 Ubuntu、systemd `DynamicUser`、Node.js 20+、Cockpit 與已啟用密碼保護的 Pi Web。本機 Cockpit 使用 `127.0.0.1:9090`，Pi Web upstream 為 `127.0.0.1:30141`。不同設備需先依實況調整並驗證。

```bash
# 只提供 LAN
sudo bash pi-web-integration/install.sh 192.168.2.46 19094
# 同時提供 LAN 與設備上的 VPN IPv4
sudo bash pi-web-integration/install.sh 192.168.2.46 19094 100.112.140.82
# 同時提供 Cloudflare HTTPS（需先部署 pwa-gateway，並設定 Cockpit Origins）
sudo bash pi-web-integration/install.sh 192.168.2.46 19094 100.112.140.82 https://console.example.com
```

安裝器不修改 Cockpit 或防火牆設定。Cockpit 需允許 HTTP，例如在既有 `[WebService]` 的 `Origins` 加入所使用的 `http://<ip>:9090` 並保留既有來源，確認 `AllowUnencrypted` 設定，再依 Cockpit 文件重啟服務。防火牆須分別限定 LAN 網段與 VPN 介面、目的 IP 和 19094/tcp；不要開放原生 Pi Web port。參考主機的 VPN 規則限 `tailscale0` 和 VPN IP。VPN 介面未就緒時服務可能暫時失敗並由 systemd 重試。

若曾安裝 VPN／公開 gateway，後續重裝時請繼續提供第三／第四個參數；省略參數不會移除先前服務或防火牆規則，但套件會依此次參數更新入口清單。舊版建立的憑證保留在磁碟但本版 gateway 不使用。安裝過程不會重啟 Pi Web。

使用 `http://<已設定的IP>:9090` 或已設定的公開 HTTPS 網址登入，點「工具 → Pi Web」，再登入 Pi Web。要變更 IP／網域，需同步調整 Cockpit Origins、systemd、套件設定及防火牆。

## Cloudflare 同網域入口

公開入口使用 `/pi-web/`，經 PWA gateway 轉到 `127.0.0.1:19095` 的 `woowtech-piweb-gateway-public.service`。其 `PI_GATEWAY_PUBLIC_ORIGIN` 必須是明確的 HTTPS origin，不能是任意訪客送來的 Host／代理標頭。它以 HTTPS 協定標頭向 loopback Cockpit 檢查 Secure session，並繼續要求 Pi Web 自己的密碼登入；Cockpit cookie 不會轉交 Pi Web。

目前 Pi Web 的 Next.js 成品使用根目錄資源及 API。PWA gateway 因此保留 `/_next/`、`/api/`、`/icons/`、`/paseo-web/`、Pi 登入／Omnigent／Paseo 頁面等路徑給此整合；Pi iframe 的文件及 RSC 導航也送往 Pi。`/cockpit/` 與 `/woow-pwa/` 仍送往各自的服務，最上層 `/` 開啟 Cockpit。SSE 關閉反向代理緩衝，WebSocket 支援 Upgrade。部署新版本 Pi Web 時須重新核對新增路徑。

Pi Web 原生的 `/sw.js` 要求控制整個 `/`；公開整合不提供這支 worker，避免其離線快取影響 Cockpit。嵌入模式依賴網路，Cockpit PWA 本身的 manifest 與安裝功能由 PWA gateway 提供。Pi Web 與 Cockpit 共用網站 origin，應視為同一個受信任的網站；本整合不提供兩者之間的 origin 隔離。

如果同一瀏覽器先前用 HTTPS 登入同一個 IP，轉為 HTTP 時可能因既有 `Secure` Cockpit cookie 阻擋新 cookie 而反覆回到登入頁。可先以無痕視窗測試，或清除該 IP 的網站資料後重新登入；清除網站資料也可能使該 IP 的其他服務登出，但不會刪除伺服器上的對話。

## 驗證與操作限制

- 每個請求向 `127.0.0.1:9090/cockpit/login` 驗證 Cockpit 的 HTTP session，再檢查 Pi Web 密碼保護；在長 SSE／WebSocket 期間定期重新確認。
- `/cockpit/login` 並非 Cockpit 官方承諾穩定的外部 REST API。Cockpit 升級前後必須重新驗證登入、登出、長連線及授權；驗證失敗時 gateway 拒絕代理。
- Gateway 不將 Cockpit cookie 傳至 Pi Web，並只允許 Pi Web 的 session cookie 從 upstream 設定。狀態變更檢查 Origin，並檢查 Host 與跨站請求。
- 所有擁有兩組登入資訊的人操作同一份 Pi Web 資料；沒有依 Cockpit 使用者隔離對話或權限。

```bash
node --test pi-web-integration/tests/*.mjs
sudo systemctl status woowtech-piweb-gateway.service woowtech-piweb-gateway-vpn.service
```

不需要此功能時可停用相應 gateway，並個別移除防火牆規則；不會移除 Pi Web 服務或對話資料。

## Cockpit 主題同步

從 Cockpit 嵌入開啟 Pi Web 時，入口會依 Cockpit 的淺色、深色或系統預設切換 Pi Web 的顯示與品牌藍；直接開啟 Pi Web 仍使用 Pi Web 自己的主題偏好。此同步不修改瀏覽器儲存的 `pi-theme`。入口只接受來自已設定 Cockpit origin 的主題訊息。Pi Web 升級後應重新驗證 HTML 注入、登入、對話、WebSocket 與主題切換。
