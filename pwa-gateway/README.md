# Cockpit PWA gateway

The optional gateway listens on 127.0.0.1:29091 and forwards Cockpit HTTP and WebSocket traffic to 127.0.0.1:9090. It adds the PWA manifest to HTML without changing Cockpit's package files. The manifest and icons are served locally by the gateway. This listener is intended to be reached only through a trusted TLS-terminating tunnel; the direct LAN/VPN Cockpit listener remains unchanged.

Install with `pwa-gateway/install.sh` as the Podman owner. Add the chosen public HTTPS origin to `/etc/cockpit/cockpit.conf` `WebService.Origins`, together with existing local origins, and set `ProtocolHeader = X-Forwarded-Proto`. Configure the tunnel route to `http://localhost:29091`. Restart Cockpit to apply an origin change; this closes existing Cockpit sessions. Make sure the reverse proxy and tunnel preserve WebSocket upgrades. An HTTPS origin is needed for normal remote PWA installation.

The gateway never caches Cockpit pages or credentials and has no offline administrative functionality. Manifest and icons are non-sensitive. Cockpit's own authentication and authorization remain active. Restrict access to the gateway listener: it trusts the upstream protocol header from the local tunnel.

Run `npm ci`, then `PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chrome node pwa-gateway/test.mjs` for a local browser installability check. Set `COCKPIT_URL` to the public HTTPS origin and `COCKPIT_PASSWORD` in the environment to additionally check authenticated navigation and the WebSocket. A Chromium check does not replace an Android device installation test.
