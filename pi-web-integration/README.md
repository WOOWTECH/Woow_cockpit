# Cockpit Pi Web 側邊欄

Cockpit 362 的獨立 package 與限制來源的 HTTPS gateway，讓使用者從側邊欄開啟主機目前既有的 Pi Web。Pi Web 自己的密碼登入保留；gateway 必須先確認 Cockpit 工作階段，而且 Pi Web 獨立密碼保護未啟用時會拒絕代理。使用同一台 Pi Web 的既有資料；不新建或重啟 Pi Web。

## 本機部署及使用

需 Ubuntu、systemd 具有 `DynamicUser`、`LoadCredential`、Node.js 20+、OpenSSL、Cockpit 與受密碼保護的 Pi Web。執行前先依設備實況確認 Cockpit CA 和 pi-web upstream；目前 systemd template 的 Cockpit 憑證是本機 `/etc/cockpit/ws-certs.d/0-self-signed.cert`，服務連 `127.0.0.1:9090`；Pi Web 在 `127.0.0.1:30141`。憑證更新／其他環境需更改設定並重新驗證。請先核對已可信 source。

```bash
sudo bash pi-web-integration/install.sh 192.168.2.46 19094
sudo systemctl status woowtech-piweb-gateway.service
```

安裝套件到 `/usr/local/share/cockpit/woowpiweb/`，gateway 到 `/usr/local/libexec/woowtech-piweb-gateway.mjs`，systemd unit 到 `/etc/systemd/system/`。首次產生自簽 TLS 憑證於 `/etc/woowtech-cockpit/piweb-gateway/`；private key 僅 root 可讀，systemd 用 credentials 提供給隔離的動態使用者。重裝不自動換證；憑證更新和多設備部署需要另行規劃。

此安裝器**不自動修改防火牆**。若該設備使用 UFW 且只允許特定管理網段，需由管理者允許選定地址與 port。參考機的配置只允許 `192.168.2.0/24` 連到 `192.168.2.46:19094`，未開放 Pi Web 原生 `30141`。

重新登入 `https://<設定的IP>:9090` 後，在「系統 → Pi Web」開啟。Pi Web 保留獨立登入。第一次使用時，新入口的自簽憑證在瀏覽器中未必受信；如果 iframe 無法載入，使用頁面上「在新視窗開啟」檢查並依設備的憑證政策完成信任，再返回 Cockpit 重新整理。建議正式出貨使用設備的可信憑證與受控主機名稱；勿在未知設備上盲目接受憑證。

## 操作與安全邊界

- gateway 只綁定安裝時的指定 IPv4；package 僅對相同 hostname 開啟此入口。Cloudflare Tunnel、其他 IP、DNS 與跨站 cookie 均未驗證，頁面會提示不支援。IP 變更需重新規劃憑證、網路與設定；不可僅改前端網址。
- 每個 HTTP 請求先向本機 Cockpit `/cockpit/login` 驗證 Cockpit cookie，再確認本機 Pi Web 的密碼保護已啟用；Pi Web 自己繼續驗證它的 session。gateway 在長 SSE／WebSocket 期間定期檢查，Cockpit 登出後關閉連線。
- `/cockpit/login` 是本機 Cockpit 的 session 機制，並非 Cockpit 官方承諾的穩定外部 REST API。此整合已針對 Cockpit 362 實測，Cockpit 升級前後必須重新做授權、登入和登出回歸測試；無法驗證時 gateway 拒絕通過。
- 去除傳至 Pi Web 的 Cockpit cookie；只允許 Pi Web 的 session cookie 由 upstream 設定，防止跨 port 的同 host cookie 碰撞。動態使用者、systemd credentials 與 `ProtectHome` 降低代理對本機帳號的暴露。
- 要能使用 Pi Web，仍須知道 Pi Web 密碼。任何同時擁有 Cockpit 登入與 Pi Web 登入的人都會操作同一個 Pi Web 服務身分與資料；本整合沒有提供逐 Cockpit 使用者的 Pi 對話隔離或權限隔離。
- gateway 對狀態變更檢查 Origin，限定主機位址並阻擋跨站；代理透過 localhost 連接 Pi Web，並在 Pi Web 的密碼保護無法確認時 fail closed。Pi Web 執行能力仍由現有服務本身決定。
- Pi Web 內部分僅在瀏覽器連到 loopback 時可用的功能（例如在本機檔案管理器開啟）在 LAN 入口可能不可用。模型服務與第三方工具的可用性由其各自設定決定。

## 檢查與回退

```bash
node --test pi-web-integration/tests/gateway.mjs
sudo systemctl status woowtech-piweb-gateway.service
# 暫時停用此整合；不影響 Pi Web 和 Cockpit 本身
sudo systemctl disable --now woowtech-piweb-gateway.service
```

要完全卸除時，管理者在停用後移除本整合的 package、gateway 和 unit，並個別刪除 UFW 中對應的規則；key/cert 是否保留供日後恢復應另行決定。此腳本不清理任何 Pi Web 對話或資料。驗收應覆蓋未登入、獨立 Pi 登入、Cockpit 登出撤銷、惡意 Origin、截流登入、SSE、模型回覆、畫面 RWD 與真實瀏覽器憑證信任。
