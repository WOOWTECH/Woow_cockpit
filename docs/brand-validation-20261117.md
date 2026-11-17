# Dual-brand validation — 2026-11-17

Version `2026.11.17.1` adds woowtech/apporo presentation profiles to the same
Cockpit implementation. It does not fork application or backup engines.

## Sources

Apporo materials were collected from the owner's MacBook source checkouts.
Original company SVGs were additionally checked byte-for-byte against the
pinned GitHub source. See [asset provenance](../brands/apporo/asset-provenance.json)
and [brand attribution](../brands/apporo/NOTICE.md). No credentials, private
runtime configuration, proprietary fonts, or host screenshots are bundled.

## Validation boundary

- Python installer/backend tests: 1,056 passed, including brand selection,
  repeated installation, file drift, rollback, customer data preservation,
  asset validation, scheduled backups and unchanged helper/backup-engine bytes
  between the two brand variants.
- Pi proxy contracts: 9 passed, including both brand palettes, invalid-profile
  rejection, LAN/VPN/public-origin guards, independent authentication, and
  unchanged cookie forwarding restrictions.
- Installed UI fixtures: both brands use the same application, 10 service and
  79 backup browser scenarios. They exercise links, group controls, permissions,
  logs, uploads/downloads, restore confirmations/results, key handling,
  retention, scheduling, keyboard navigation, responsive layouts and themes.
- Apporo contrast fixes were rechecked in all four relevant theme/keyboard
  scenarios. The final installed two-brand matrix passed in CI, including Pi's
  live light/dark/auto theme messages and preserved standalone preferences.
- Generated PWA manifests and icons were checked for both brands; isolated
  browser profiles installed each PWA and launched it in a standalone window.
  PWA IDs, scopes and proxy routes are unchanged.
- Native Cockpit login DOM was inspected with browser-only Apporo assets at
  390 and 1440 pixels in light/dark modes. No login was submitted. Primary
  buttons, borders and keyboard focus use the appropriate gold; no horizontal
  overflow was observed. Those local captures are not committed.

The final [CI run](https://github.com/WOOWTECH/Woow_cockpit/actions/runs/44026347414)
tested the merge of the brand change with the scheduled-backup change from
PR #16. Its Git tree `d85fb2ca56c8d14f602ff80da8ba3e58d8d1fbbb` exactly matches
merged main commit `73871247139a054de07c2e4275a6108aa2cd5bb0`.
The distribution pins this integrated functional source for both brands.

Fixtures do not operate customer services. These checks are not a new physical
appliance installation, a cross-host restore rehearsal, or an end-to-end test
of every SaaS application. No running customer's host was rebranded in this work.

## Scope and compatibility

The shared management surfaces are branded: Cockpit login/native page styles,
sidebar, applications, service management, backup UI, reference gallery,
PWA and the embedded Pi theme. Pi Agent and third-party product identities stay
unchanged. Scheduled backups are included in the common implementation and
the two-brand browser matrix. SaaS applications' internal frontends and the
historical optional `woowbackupdesign` prototype are outside this presentation
profile.

Stable service/package IDs, paths, URLs, backup filenames, legacy key titles,
archive formats and legal notices intentionally retain their technical names.
For complete management-brand switching and rollback, use the coordinated
distribution action; standalone `manage.py rollback` does not restart Pi or
rerender the separately installed PWA. See [brand profiles](../brands/README.md).
