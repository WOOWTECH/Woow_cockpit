# Fixed fixture API source notes

These public EMQX5.8.9 source references informed the generated fixtures, not a native-pass claim:

- [emqx_psk.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_psk/src/emqx_psk.erl): `import_config` applies the PSK root; the file importer splits identity/secret on its configured separator; `on_psk_lookup/2` returns the stored value. The fixture compares only equality to its own synthetic value and prints a boolean.
- [emqx_psk_schema.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_psk/src/emqx_psk_schema.erl): enable/init_file/separator/chunk_size are ordinary configuration fields. No TLS callback/code is imported.
- [emqx_authz_mnesia.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_auth_mnesia/src/emqx_authz_mnesia.erl): exported management function `store_rules/2` normalizes ordinary rules; destroying the source clears its table. The changed-ACL case uses the management API to create one harmless synthetic rule and requires it survive product's disable/remove ordering.
- [emqx_rule_funcs.erl](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_rule_engine/src/emqx_rule_funcs.erl): jq/2 is an exported rule function. Filters are fixed `.fixture` or `env.WOOW_R4_DUMMY`; no input can supply a filter, filename, broad environment query or external sink.

The offline tests validate input and execution boundaries. Vendor schema handling, Erlang expressions and these native assertions still need the coordinator-reviewed exact-image case lease. A native failure must be retained and diagnosed; it must not be converted into a skipped check.
