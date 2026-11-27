# Retainer application configuration migration

Code-only fix based on d9957df. Retainer is an HA application data root, together
with its message table, rather than target operational configuration. The existing
root export selection now includes retainer when actually observed on the source;
operational restoration no longer overwrites its imported backend, storage, expiry,
limits or indexing configuration. No invented root/default and no RAM-table dump.
Target node/listeners/dashboard and original authorization policy remain preserved.

Primary pinned source: public EMQX v5.8.9 checkout a8319fe:
- apps/emqx_retainer/src/emqx_retainer_schema.erl fields(mnesia_config): storage_type
  enum ram/disc, default ram.
- emqx_retainer_mnesia.erl create/1 and create_table/5, lines143-200: ram maps to
  ram_copies, disc to disc_copies; existing table copy type is changed to requested
  storage. update/2 returns need_recreate.
- emqx_retainer.erl update_config/5, lines340-390: backend configuration changes
  recreate context, including the above table storage conversion.
- apps/emqx_management/src/emqx_mgmt_data_backup.erl do_import/2 lines670-681:
  configuration import precedes table import. restore_mnesia_tab lines740-754 uses
  keep_tables, explicitly retaining target schema rather than archived schema.
- product _package_candidate stops candidate before exporting its volume. Retained
  RAM rows surviving import counts therefore do not prove restart durability.

Named existing b1-source/{arm,x86}/emqx-api.json were parsed privately in memory:
retainer storage_type disc observed in both, ram not observed. No credentials,
file bodies, topics or payloads printed/copied. Historical API observation is not
an actual source/candidate/postboot native storage receipt or archive binding.

Validation: 24 host candidate-flow/package tests pass. Added actual product entry
fixture simulates imported disc+expiry configuration against target RAM and checks
operational restore retains source retainer and target node/ports/ACL. This is not
native import or restart proof. The older test_ha_emqx suite already fails on the
unchanged base (9 failures, 1 error); not corrected by weakening current guards.

Owner next: fresh actual product run must prove source export contains retainer,
candidate storage is disc_copies, and post-package boot retained payloads match the
existing independent oracle. Keep full row counts and MQTT checks unchanged.
Source RAM remains RAM; this change does not promise its restart durability.
No lab operations performed for this commit; main retains dev-d ownership.
