# Cockpit PWA gateway

The optional gateway listens on 127.0.0.1:29091 and forwards Cockpit HTTP and WebSocket traffic to 127.0.0.1:9090. It adds the PWA manifest to HTML without changing Cockpit's package files. The manifest and icons are served locally by the gateway. This listener is intended to be reached only through a trusted TLS-terminating tunnel; the direct LAN/VPN Cockpit listener remains unchanged.

Install with `pwa-gateway/install.sh` as the Podman owner. Add the chosen public HTTPS origin to `/etc/cockpit/cockpit.conf` `WebService.Origins`, together with existing local origins, and set `ProtocolHeader = X-Forwarded-Proto`. Configure the tunnel route to `http://localhost:29091`. Restart Cockpit to apply an origin change; this closes existing Cockpit sessions. Make sure the reverse proxy and tunnel preserve WebSocket upgrades. An HTTPS origin is needed for normal remote PWA installation.

The gateway never caches Cockpit pages or credentials and has no offline administrative functionality. Manifest and icons are non-sensitive. Cockpit's own authentication and authorization remain active. Restrict access to the gateway listener: it trusts the upstream protocol header from the local tunnel.

For Pi Web in the sidebar over the public HTTPS origin, also install `pi-web-integration/install.sh` with the exact public origin as its fourth argument. This creates a loopback-only, session-validating Pi gateway on 19095. Nginx routes `/pi-web/` plus the native Pi Web/Next.js asset, API, iframe and RSC navigation requests to it; Cockpit's `/cockpit/` endpoints retain priority. See the [Pi Web integration](../pi-web-integration/README.md) for the reserved paths and authentication boundary.

Run `npm ci`, then `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chrome node pwa-gateway/test.mjs` for a local browser installability check. Set `COCKPIT_URL` to the public HTTPS origin and `COCKPIT_PASSWORD` in the environment to additionally check authenticated navigation and the WebSocket. A Chromium check does not replace an Android device installation test.

For an optional installation and standalone-window test, run `xvfb-run -a env PWA_HEADFUL=1 PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chrome COCKPIT_URL=https://your-host.example node pwa-gateway/install-test.mjs`. It installs into an isolated profile, selects the browser's standalone-window preference, launches the app, checks its display mode, and removes the test installation. `COCKPIT_PASSWORD` also enables a real login inside the installed app. See [the public deployment validation](VALIDATION.md) for the tested configuration and remaining boundaries.
# 品牌選擇

PWA 與 Cockpit 共用 `brands/woowtech/brand.json`、`brands/apporo/brand.json`。
先以 `scripts/manage.py install --brand apporo` 安裝品牌，再執行本目錄的
`install.sh`；安裝器會讀取 `/etc/cockpit/branding/brand.json`，不會因省略
`BRAND` 而將 Apporo 換回 WOOW。若明確提供不同的 `BRAND`，會在寫入前拒絕。

名稱、主色與原始圖示依品牌產生；PWA 的 `id`、scope、start_url、服務名稱
及 Cockpit／Pi Web 代理路由相同。既有已安裝 PWA 由瀏覽器重新讀取 manifest
後更新顯示名稱／圖示，更新時間由瀏覽器決定。

不啟動服務的產物驗證：

```bash
python3 pwa-gateway/render.py --brand apporo --output /tmp/apporo-pwa-preview
node tests/pwa-brands.mjs
```

後者用隔離 HTTP loopback fixture 驗證兩品牌的瀏覽器安裝及獨立視窗啟動，
不會登入或變更正式 Cockpit。
