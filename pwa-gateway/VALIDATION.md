# Public Cockpit / PWA validation — 2026-11-13

Public URL: `https://cockpit-openclaw.woowtech.io/`.

## PaaS configuration

- Workspace: `pi-agents` (28).
- Security Access: `pi-web woowtechopenclaw` (61).
- Application route: `cockpit-openclaw` (120), origin `http://localhost:29091`.
- Access Control is disabled for this route; no Cloudflare Access application was created. Cockpit authentication remains required.
- Existing subscription: 6 routes; this adds the sixth. No subscription or seat change was needed.
- Created through the production PaaS route model, including its quota, prefix availability, operator synchronization and DNS receipt checks. Existing route names, targets and protection flags were checked for changes.

## Live results

- Anonymous public GET: HTTP 200 with Cockpit login, no Access login redirect.
- HTTPS certificate validated normally; no insecure-certificate bypass in browser tests.
- Correct HTTPS/WSS Content Security Policy and Secure/HttpOnly Cockpit cookie attributes.
- Public manifest: valid, display `standalone`, two PNG icons at 192 and 512 pixels.
- Real public Cockpit login and `/system` navigation pass; WSS remains connected.
- Login and authenticated shell both link to the manifest.
- Chromium reports no manifest or installability errors. `beforeinstallprompt` was observed.
- Chromium installed the application into an isolated test profile. A windowed Chromium test under Xvfb launched it with the browser's standalone preference and confirmed `(display-mode: standalone)` is true, including after a real Cockpit login inside the installed app. The optional `install-test.mjs` reproduces this test and removes the test installation/profile afterwards.
- Mobile-sized login viewport: 390px content width and 390px document width, without horizontal overflow.
- Other public routes still reach their expected authentication or landing response: Pi Web and tunnel GUI redirect to Access; OpenDesign returns its own 401; Hermes redirects to its login; Odoo redirects to `/odoo`.

## Deployment and boundaries

The gateway is the rootless Podman container `woow-cockpit-pwa`, supervised by `woow-cockpit-pwa.service` generated from its Quadlet. It listens only on `127.0.0.1:29091`. Observed idle memory was approximately 2.2 MB; this is a measurement, not a capacity guarantee.

The origin remains HTTP locally. Cloudflare supplies public HTTPS; no local TLS certificate was added. `/etc/cockpit/cockpit.conf` allows this specific public origin and trusts `X-Forwarded-Proto` from the local proxy. The gateway injects manifest/theme/icon links into HTML and forwards HTTP and WebSocket traffic to Cockpit on 9090. It does not cache administrative content or implement offline operations.

Desktop Chromium automation is not a physical Android or iOS installation test; no phone was attached to cluster1 during this run. The Pi Web sidebar now also supports the exact configured public HTTPS origin through the loopback Pi gateway; see the integration tests and notes below.

No deployed application service was stopped or restored during these checks. The Pi Web follow-up uses its own new test conversation without tool calls.

## Pi Web public ingress follow-up

The Pi Web wrapper initially reproduced the reported hidden-frame error because it only allowed LAN/VPN HTTP origins. The new wrapper accepts the configured public HTTPS origin and opens `/pi-web/` on that same origin. A separate DynamicUser system service listens on `127.0.0.1:19095`. It checks the secure Cockpit session, requires Pi's independent authentication and strips Cockpit credentials before forwarding to the native server.

The native server's Host allowlist initially rejected the new public domain. The ingress now validates the external Host/Origin first, then uses a fixed loopback authority on the internal hop and rewrites loopback redirect locations. This did not require modifying the native Pi configuration or restarting Pi Web. The public origin remains explicit and visitor-supplied forwarding headers do not control the session-validation protocol.

Live browser checks cover independent Pi login, light/dark synchronization with the exact brand blue, mobile overflow, and absence of root-scope service-worker registrations. The theme bridge has an explicit Nginx route alongside the native Next.js assets, APIs and iframe/RSC navigation paths. Pi's own `/sw.js` is excluded so that it cannot control the entire Cockpit origin.

A real test conversation used the existing LiteLLM provider and `chatgpt/gpt-5.6-luna` model. Its persisted session contains one user message, an assistant-role reply with the requested unique marker, and zero tool calls; the reply took approximately 4.5 seconds. This checks the assistant entry rather than matching the marker in the user's prompt.

Deployment backup: `/var/backups/woowtech-cockpit-pi-public/20261113T083515Z` on woowtechopenclaw. The installer requires the public origin as its fourth argument. Run `tests/pi-web-public-live.mjs` with `COCKPIT_PASSWORD`, `PI_WEB_PASSWORD`, and optionally `COCKPIT_URL`. `PI_WEB_CHAT_TEST=1` additionally sends one prompt in a new test session and checks assistant-role output and its event stream; it is opt-in and is not part of CI.
