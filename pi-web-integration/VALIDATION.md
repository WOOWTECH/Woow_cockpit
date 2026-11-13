# 參考主機驗證紀錄

2026-11-13 在 Ubuntu 24.04、Cockpit 362、現有本機 Pi Web 環境驗證。此紀錄不是其他設備的適用性證明。

- 本機 Pi Web 由使用者 systemd `pi-web.service` 運作，原生入口只監聽 `127.0.0.1:30141`；本整合沒有重新啟動 Pi Web。
- systemd gateway 以 `DynamicUser=yes`、`NoNewPrivileges=yes` 啟動；只綁定參考設備區網地址與指定 port。UFW 只允許管理子網的指定目的地址與 port。
- 未登入 Cockpit 的請求回 401；登入 Cockpit 但未登入 Pi Web 時，仍必須通過 Pi Web 登入。實際用 Cockpit 選單登出後，舊工作階段被拒絕。
- 測試拒絕錯誤 Host 與跨來源 POST；fixture 另驗證禁用 Pi Web 密碼時回 503、Cockpit cookie 不被轉送到 Pi Web，以及只接受 Pi Web session 的 Set-Cookie。
- 實際在 Cockpit 側邊欄嵌入現有 Pi Web，完成獨立登入，讀取對話清單 API，並選用免費模型送出短測試；在助理訊息區確認模型的實際回覆。這包含此次對話所需 SSE，但不代表所有可能的 Pi Web 插件或外部服務均已驗收。
- 檢查 Cockpit 外層頁面 1440、1024、768、390 與 320px 寬度；此項檢查不等同各實體手機瀏覽器驗收。WebSocket 代理通過本機 mock upgrade；尚未在實際 Pi Web 子功能實測 WebSocket。
- 本機 Chromium 未信任 gateway 自簽憑證時會拒絕載入；互動驗證為忽略測試憑證錯誤的瀏覽器環境，使用者須先依政策信任入口憑證。此階段未驗證客戶實體裝置的手動信任流程或受信憑證。
- 僅驗證 `192.168.2.46` 的 LAN 入口。另一台 LAN 裝置的連線、Cloudflare 域名入口、不同系統瀏覽器和 Pi Web 所有第三方擴充尚未驗證。部分 Pi Web 僅允許 localhost 的 OS 本機操作在 LAN 入口會呈現不可使用。

## 同日 VPN 擴充

- 新增 `100.112.140.82:19094` 專用 gateway 與自簽憑證，Pi Web 原服務仍只監聽 loopback。UFW 規則限定 `tailscale0` 與 VPN 目的 IP。
- 從本機瀏覽器使用 VPN IP 的 HTTPS Cockpit 登入，再從側邊欄登入既有 Pi Web、讀取對話清單、使用免費模型取得助理實際回覆；檢查 1440、1024、768、390、320px。HTTP Cockpit 會提供切換 HTTPS 的提示。
- 實測未登入 401、惡意來源與 Host 403，並確認 Cockpit 登出後舊工作階段失效。瀏覽器測試允許自簽憑證；另一台 VPN 裝置的實際網路路徑與手動信任流程未驗證。

## 同日 HTTP 區網與 VPN 調整

使用者要求 LAN 和 VPN 均改為 HTTP；以下為本次最終狀態，取代上述 HTTPS 入口與自簽憑證描述。Cockpit HTTP session 必須用本機 Cockpit HTTP 端點驗證，不能用 HTTPS 端點驗證；gateway 已調整。服務分別監聽 LAN 與 VPN 指定 IP，原生 Pi Web 仍只監聽 loopback。LAN HTTP 未加密；VPN 是否加密取決於 VPN。未部署 Cloudflare 外網入口。

- 實際由本機 Chromium 使用 LAN 和 VPN IP 的 HTTP Cockpit 開啟 Pi Web，完成獨立登入、讀取對話清單及五種畫面寬度檢查；VPN HTTP 入口另實測得到模型回覆。這是本機對自身位址的測試，並非另一台設備跨網路的驗證。
- LAN 與 VPN 分別驗證兩階段登入、錯誤 Origin/Host 遭拒絕，以及 Cockpit 登出後舊工作階段失效。外網 HTTPS 與 Cloudflare Tunnel 不在本次部署範圍。
- LAN 模型也實際回覆了「测试成功」。自動測試原本只接受繁體字而逾時；檢查助理訊息後確認回覆是簡體字，故不應把該次斷言逾時視作模型未回覆。
- 重現先 HTTPS 登入再切 HTTP 的登入循環：Cockpit 登入端點成功後，瀏覽器因既有 Secure cookie 未接收新的 HTTP cookie，回到登入頁。移除舊 cookie 後，同一瀏覽器實測 HTTP 登入成功。

## 側邊欄位置與全版面

Pi Web 移至「工具」，右側嵌入頁移除標題、說明與外層間距。以實際 Cockpit 登入後確認 Pi Web 可讀取對話清單，並在 1440、1024、768、390、320px 寬度檢查 iframe 貼齊且填滿 Cockpit 的內容區；這不代表所有實體行動裝置皆已驗證。
