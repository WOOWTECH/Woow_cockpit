# Brand profiles and install-time rendering

The same Cockpit implementation supports `woowtech` and `apporo`. Profile selection changes presentation, not package IDs, helper paths, service names, authentication, application grouping, or backup formats. The installer never edits this checkout's assets.

```bash
# Inspect an explicit brand change first.
python3 scripts/manage.py plan --brand apporo
# On the intended device only, after reviewing the plan:
sudo python3 scripts/manage.py install --brand apporo
sudo python3 scripts/manage.py verify
# A later update without --brand keeps the installed brand.
sudo python3 scripts/manage.py install
```

The CLI resolves an omitted `--brand` from `/etc/cockpit/branding/brand.json`. A new device without that file defaults to woowtech. Invalid existing schema/id or malformed JSON fails without writing; an explicit `--brand` selects a profile. The Python `desired_files(..., brand='woowtech')` default remains compatible with existing callers. `--root` places everything below an isolated Ubuntu fixture root and does not deploy to the live host.

`--no-preview`, `--no-services`, and `--no-backup` retain their original meaning: skipped existing packages remain on disk and are not updated. Do not use these flags for a complete brand switch, because skipped packages retain their prior presentation. Existing local screenshots are preserved; they may show the former brand until explicitly replaced with new, reviewed captures. No customer screenshots are bundled.

## Shared Python interface

```python
from scripts.brand_profile import (
    load_profile, asset_mapping, render_file, render_runtime_json,
)

load_profile(brand: str, *, source_root: Path | None = None) -> dict
asset_mapping(profile: dict, *, source_root: Path | None = None) -> dict[str, Path]
render_file(relative_path: str, data: bytes, profile: dict) -> bytes
render_runtime_json(profile: dict) -> bytes
```

`source_root` defaults to the repository containing the module. `load_profile()` validates the schema, ID, names, both palettes, and every required asset; missing official assets fail before any installation. It returns a dict with asset strings relative to `brands/<id>`. Pass the same `source_root` to `asset_mapping()` when loading an alternate source. That function returns role → absolute regular `Path`, rejecting escapes and symlinks. The woowtech profile alone can refer back to original assets elsewhere inside the same repository; apporo assets remain under its own directory.

`render_file()` takes a repository-relative source path, never an installed target path. Only listed CSS, display HTML and the backup UI's user-facing prose are rendered. Other files are returned byte-for-byte. Backup engine modules and helpers, backup/key export filenames, legacy key titles, `apps-catalog/apps.js`, native Podman integration, and Pi/PWA source are never rendered. For woowtech, all source payloads pass through byte-for-byte.

The installer also uses `branding_assets()` to map official source bytes to existing installed logo URLs and explicit dark variants. It preserves the old URLs to avoid route/consumer changes. This is a copy at deployment time, not artwork generation, recoloring, or source modification. All old apporo-mode logo aliases resolve to official apporo assets, including aliases whose historic names contain `-blue` or `-white`.

## Public runtime contract

The installer manages `/etc/cockpit/branding/brand.json` as root-owned 0644, records its SHA-256, verifies it, and restores it through the existing transaction rollback. It is public branding data and contains no source filesystem paths or credentials. Required shape:

```json
{
  "schema": 1,
  "id": "apporo",
  "display_name": "apporo 設備管理",
  "company": "APPORO UNION INC.",
  "colors": {
    "light": {"primary": "#8B6B24", "hover": "#8B6B24", "on_primary": "#FFFFFF"},
    "dark": {"primary": "#C49E53", "hover": "#C49E53", "on_primary": "#1C1C1E"}
  }
}
```

The generated JSON also includes optional surface colors and `assets` mapped to stable paths relative to `/etc/cockpit/branding`. Consumers must read required keys and permit additive keys. Source provenance is not installed publicly. Pi's gateway consumes this JSON at startup; PWA rendering consumes the source profile through `load_profile()`. Run their separate installation flows to refresh those components after a brand switch; `manage.py` does not restart the gateway or rebuild the PWA.

For woowtech, runtime `primary` and `hover` are both `#6183FC`, and `on_primary` is `#111A3A` in both modes, preserving the original Pi bridge. Existing woowtech Cockpit CSS remains unchanged, including its own light hover/text treatments. Do not infer that every historic CSS token equals the runtime bridge palette.

## Approved inputs and presentation adaptations

Apporo's company name is APPORO UNION INC. The management edition is **apporo 設備管理**. Apporo smart is desktop agent collaboration, Apporo platform is Odoo ERP, Apporo aiot is the HA app, and Assistant is a separate product. This installer does not rename or claim that the existing Pi Agent/Pi Web service is Assistant.

Apporo source assets live under `apporo/assets/company/` and `apporo/assets/smart/`; their sources and SHA-256 hashes are recorded in `apporo/asset-provenance.json`, with attribution in `apporo/NOTICE.md`. The official company lockup is square and vertical, with gray artwork and a transparent background. Login, sidebar and reference-page logos have no background plate. Light mode displays the original dark gray artwork; dark mode uses a CSS filter to display it white, preserving the original vector geometry and transparency. This presentation change was requested by the project owner on 2026-11-17; source assets remain byte-identical. The login box is `min(40%, 8rem)`, exactly 80% of its previous `min(50%, 10rem)` size, retaining its square aspect ratio and 80% inner image size. The compact sidebar uses the official mark plus a normal UI label. Apporo reference pages share Cockpit's theme preference and live changes. No gold or blue logo is fabricated.

The profile supplies the confirmed primary colors and neutral backgrounds. Unspecified hover uses the same primary. System fonts replace the existing custom font stack in apporo's rendered CSS. Cards at 16px and controls at 8px are management adaptations from the Smart ramp, not a corporate rule. Brand washes are computed as 10% primary + 90% page in sRGB and serialized as HEX for browser and contrast-tool compatibility. Native status/error colors and terminal palettes remain unchanged.

The static gallery preserves its role as a reference page; historical comparison content and imported screenshots are not new product documentation. The older `woowbackupdesign` prototype is not supplied by this installer; its independent legacy theme overlay is outside this implementation scope.

## Validation and rollback

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_brand_install tests.test_manage -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -q
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_source.py
```

Brand tests install only into temporary roots. They cover default/preserved selection, explicit switching, missing assets, invalid schemas/colors/paths, symlinks, exact official asset bytes, backend/app byte parity, idempotency, permissions, drift, rollback, and preservation of device settings/data. Also run the separate browser, PWA and Pi suites for both brands when changing presentation or the runtime contract. Use the transaction ID reported by install with the existing `rollback` command; it refuses to overwrite newer operator changes.

`manage.py rollback` restores only its managed files. The Pi process caches its
palette at startup, and the PWA has a separate installation. For an appliance
managed by `Woow_ubuntu_version_control`, use its coordinated
`woow-release.py brand --brand woowtech` with the same approved dual-brand material
lock to switch the complete management entry back. It refreshes the PWA and
restarts active Pi gateways while preserving their LAN/VPN/public origins.
For a standalone Cockpit deployment, after restoring managed files, run
`env -u BRAND bash pwa-gateway/install.sh` as the PWA service owner and restart
only the already active Pi gateway services. Do not run the fresh Pi installer
with empty VPN/public arguments to perform a brand rollback.

The integrated main source `7387124` includes both the brand profiles (PR #17)
and scheduled backups (PR #16). Both brands share that backup engine and its
timer/retention behavior. The final CI tested the exact merged source tree,
including 1,056 Python tests and 79 backup browser scenarios per brand; see
[validation evidence](../docs/brand-validation-20261117.md).
