# E-44: conservative plugin record cleanup

This change implements cleanup of device plugin state records proven unused, while keeping HA plugin code outside the conversion boundary. It does not implement arbitrary plugin migration.

## Source trace and design distinction

Public EMQX v5.8.9 sources, with downloaded hashes and the tag object recorded in `vendor-source.json`:

- [emqx_plugins_app.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_plugins/src/emqx_plugins_app.erl#L29-L35): startup calls `ensure_installed()` and then `ensure_started()`.
- [emqx_plugins.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_plugins/src/emqx_plugins.erl#L859-L872): a state record can cause installation from an existing extracted directory, local `.tar.gz` package or another cluster node. Missing plugins are logged by `for_plugins` and do not make broker startup fail. This is why a successful broker start alone cannot establish plugin availability.
- The same module, `plugin_status` (948-978), determines running status from the application name before the first hyphen. `post_config_update` (1239-1257) acts on changed enable flags; removing an entry alone does not reliably stop its running application. This patch never removes a record whose application is running on either side.
- The same module, `plugin_data_dir` / `plugin_config_file` (1561-1593), places plugin configuration under `data/plugins/<app>/config.hocon`; binaries need not be outside the data volume. Inventory includes packages, disabled/hidden records and that data directory, and compares configuration digests without exposing values. Directory/archive presence is conservative material evidence, not a validation that every file of a plugin is usable.
- [emqx_plugins_schema.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_plugins/src/emqx_plugins_schema.erl#L42-L80): a record whose `enable` is omitted defaults to enabled; install_dir defaults to `plugins`.
- [emqx_mgmt_data_backup.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_management/src/emqx_mgmt_data_backup.erl): imported config roots are applied by registered config importers. Existing product export allowlists remain authoritative.

There are two different record origins:

1. **HA records:** source `cluster.hocon` may name arbitrary code. Existing source environment overrides force `plugins.states=[]` and the image's install directory before boot; source export excludes the plugins root, and `check_export` rejects that root and any plugin member. HA state records and binaries therefore never become candidate plugin state. This protection is unchanged.
2. **Device records:** the candidate starts with this device's configuration. Blanket clearing would disable or alter its genuine plugins. An explicit inventory on both sides now permits removal only when neither side has plugin material or a running application. Other plugin states, their order, install_dir and configuration fields are retained; the whole operational configuration is still compared against the narrowly adjusted expected configuration.

Enabled missing records require `emqx.plugin-records-remove` through the existing single-confirmation path, with complete identities contributing to its key. Disabled missing records receive `emqx.plugin-records-unused`. A new name or newly enabled missing record cannot reuse an old acknowledgement. No live device volume is modified during either check or conversion.

## Constraint and prepared choices

If this device has installed/plugin configuration material that the candidate cannot preserve, the patch stops EMQX import and names the plugin. It does not clear the record and pretend to have preserved that plugin. Examples include plugins installed only in the live container writable layer or unsnapshotted data volume, and regenerated default config differing from the device's config.

Concrete choices for such a device:

1. Keep the conservative stop (implemented). First place the device's plugin code and configuration in a reproducible image or existing preserved mounts, then repeat check/import. This keeps plugin settings and HA code protections.
2. Separately implement a bounded, no-link, exact device plugin material snapshot with file fingerprint validation and isolated restart validation. This would copy trusted **device** material only, require additional archive/resource review and a leased lab fixture; it is outside this minimal change.
3. If an owner instead wants to discard an available device plugin, design an explicit named enabled-plugin loss confirmation and verified stop/removal operation. Blanket state clearing, treating mere missing candidate binaries as permission, and importing backup plugin code are not implemented choices.

H2 package upgrade repo remains untouched; no push, package install, image pull or broker/device mutation was performed.

## Validation and native acceptance

- First operational run: 85 tests, one failed docs assertion and one erroneous test field (`names` vs public `items`); both corrected in tests/snippet. Neither was a product bypass.
- Guarded targeted run 2: 262 tests, 0 failures, 0 errors, 0 skips; 0 blocked operations and 0 shim hits. Modules: operational, candidate_flow, product, export_members, security_review, security_review2, target_guard, ha_issues.
- Final guarded operational/parity run 4: 143 tests, 0 failures, 0 errors, 0 skips, blocked=0, shim_hits=0. Run 3 found only the stale expected confirmation-id set; it was updated to include the new explicit confirmation without loosening the set equality.
- Shared guide/contract/registry edits are supplied in `integration.md`; docs unit checks explicitly include this pending snippet, so passing units do not claim those shared docs were already merged.

Native acceptance is pending a coordinator-issued lab lease. Required isolated cases: execute the fixed read-only inventory expression on v5.8.9; enabled/default-enabled and disabled missing states; a bundled/mounted plugin retained; device material/config absent or different in the candidate rejected; persisted cleaned states after candidate restart; unchanged other operational roots, HA admin/ACL/key table checks and safety rollback. Use existing isolated lab tools and sanitized evidence wrappers. No worker approval or elapsed time substitutes for that lease.

## Startup override followup

Vendor `emqx_config.erl` (`vendor-source.json`) loads base.hocon and cluster.hocon before config_files(), then overlays environment (do_parse_hocon 440-450, overlay_v1 364-366). A runtime conf update cannot promise persistence if a higher-priority startup file or EMQX_PLUGINS / EMQX_PLUGINS__STATES resets the old list. The fixed inventory now reads only the presence of such an override and refuses cleanup for that plugin; no environment value is exposed. Available plugin settings remain preserved even when intentionally overridden. Native restart proof remains mandatory.
