Separate synthetic Mnesia ACL target variant

`create_mnesia_acl_target_variant()` returns private `base` and `acl` bytes. It
starts from the existing fresh target base and replaces only its exact fixed
file-only authorization stanza. The original factory/workflow are unchanged.
Pass these bytes to `OwnerProvision.create(base, acl, bootstrap, dashboard)`;
keep its issued capability and held fixture observer. Do not replace the files
or reissue a capability across restore. Use `variant.unchanged(base=..., acl=...)`
for private pre/post byte assertions; this helper is not a substitute for actual
mount identity, file observation, product preservation, or MQTT checks.

The ordered sources are enabled file then enabled built_in_database. Global
no_match stays deny and deny_action stays ignore. File contains precisely the
lab username lab/# allow and sensor username b1/secret/# subscribe deny. Neither
a global deny nor the original gateway grant is in this variant. The ordinary
file-only factory retains both. File nomatch must reach the database; a matched
file deny remains terminal. This policy does not add any source ACL records.

Source requirements, not a cold-data completion claim:

* Existing private b1-source/{arm,x86}/emqx-api.json acl_users facts show a
  b1-gateway username allow/subscribe/b1/# rule. Only fixed-field booleans were
  checked, no credentials or private payloads emitted. Bind the chosen archive
  SHA to the existing source_profile SQL-alias case and source capture validation;
  API evidence alone does not establish archive contents.
* Before calling the retained-topic probe evidence of imported ACL behavior,
  establish the authenticated gateway is not superuser and there is no earlier
  overriding clientid rule; inspect all-rule fallback in the actual imported ACL inventory. Verify a
  successful source-known subscribe AND exact retained payload through the
  product path, plus target lab allow/sensor deny and global fallback deny.
* Preserve target file/config bytes before restore, after restore, rollback and
  restart with the existing issued observers. Runtime integration is deliberately
  left to the workflow owner; this helper performs no provisioning or lab access.

The pinned public-image fixture actually checks HOCON authorization schema and
executes native file and Mnesia authorizer components. Only its file path is
substituted to generated /input/acl.conf. It uses a fresh synthetic Mnesia table,
with the public native username key tag 1 and a synthetic copy of the known
source grant; deleting that row removes the grant. This is not an HA import,
MQTT chain, live full-broker, or commercial acceptance test. It validates schema
and component contracts, not actual imported source records or product restore.
No scanner, target reference guard, or production setting changes are included.
