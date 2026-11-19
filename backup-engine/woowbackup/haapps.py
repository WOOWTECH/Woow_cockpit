"""Home Assistant import: the one registry of importers (CONTRACT section 5 "Apps", section 9 "Home Assistant
import"). Owner: E2.

An importer maps a WOOWTECH add-on -- its slug after the repository prefix, e.g. `woow-hermes` -- to this device's
catalog app id, the name shown while that app is not installed here and the module that checks and converts it. Every
list of importable apps is derived from IMPORTERS, in this order: `hastore.IMPORTABLE` (what an uploaded HA backup
offers), `haimport.APPS` (the jobs; also the order of the import's notes and reminders) and `cli.HA_APP_IDS` (request
validation).

A module provides
* `check(work, app)` -> {target_version, blockers?, warnings?, <app id>: {...}} (the app's section of the check result);
  optionally `check_blockers(found)` -> [zh-TW] for blockers derived from the section (Odoo: no movable database);
* `convert(work, app, *convert_args, out_dir)` -> {volumes?, postgres?, dirs?, ...}: the catalog items handed to
  `adapter.import_manifest`, the rest is the module's own (its texts); `convert_args` name the job params it takes;
* `import_texts(data)` -> (notes, reminders) of a conversion.

`mcp_admin` names this device's MCP admin app of the product and `mcp_addon` the HA MCP add-on; with `engine_mcp_lines`
the engine writes the "MCP admin / claude.ai connector" reminder lines itself (batch 1); for Odoo and n8n the page does
(CONTRACT section 7 HaImport).
"""
import dataclasses
import importlib


@dataclasses.dataclass(frozen=True)
class Importer:
    app_id: str
    slug: str
    name: str
    module: str
    convert_args: tuple = ('test_mode',)
    mcp_admin: str | None = None
    mcp_addon: str | None = None
    engine_mcp_lines: bool = False

    def load(self):
        """The importer's module (imported on first use; tests patch its functions in place)."""
        return importlib.import_module(f'{__package__}.{self.module}')


IMPORTERS = (
    Importer('odoo', 'odoo18ce', 'Odoo 18', 'ha_odoo', convert_args=('odoo_database', 'test_mode'),
             mcp_admin='odoo-mcp-admin', mcp_addon='Woow Odoo MCP Server'),
    Importer('n8n', 'woow-n8n', 'n8n 工作流程', 'ha_n8n', mcp_admin='n8n-mcp-admin', mcp_addon='Woow n8n MCP Server'),
)

BY_APP = {importer.app_id: importer for importer in IMPORTERS}
BY_SLUG = {importer.slug: importer for importer in IMPORTERS}
APP_IDS = tuple(importer.app_id for importer in IMPORTERS)


def get(app_id):
    """The Importer of a catalog app id (KeyError for an app that cannot be imported)."""
    return BY_APP[app_id]


def for_slug(suffix):
    """The Importer of an add-on slug suffix, or None."""
    return BY_SLUG.get(suffix)
