Private handoff to main/Turing: imported ACL target mode

No workflow hook currently exists at base 612b0f6. This commit deliberately adds
only a selector and transport-consumer tests; it does not monkeypatch workflow
functions, duplicate the framed source parser, or start a broker. There is no
agent messaging tool in this session, so this checked-in note is the handoff.

Future owner hook:

* Add an explicit target-mode keyword, defaulting to FILE_BASELINE, separately
  from source_mode. Keep source-mode validation and frame parsing unchanged.
* At the existing provision point call target_policy_for_mode(target_mode), then
  OwnerProvision.create(policy.base, policy.acl, bootstrap, dashboard). No new
  receipts, tokens, secret sources or mount exceptions. Keep the same issued
  capability, composite observer and unchanged base/ACL bytes across the product
  operation. A mismatch must fail; do not generate a fresh policy for readback
  because the base contains an invocation-specific random cookie.
* FILE_BASELINE is byte-for-byte the existing factory result. IMPORTED_MNESIA
  uses file then enabled builtin DB with no_match=deny/deny_action=ignore. Its
  file contains ONLY target lab/# allow. Unlike the earlier limited factory,
  it contains neither sensor secret deny nor gateway grant. All source-role
  decisions must therefore come from the imported database (or global deny).
* Keep FILE baseline's current validate_source_mqtt semantics/receipt label.
  A new mode-specific validator is still needed in Turing's owned transport:
  sensor publish to b1/sensor/b1-sensor/probe must receive an explicit successful
  MQTT acknowledgement; sensor subscribe b1/secret/# must receive SUBACK 135;
  gateway subscribes retained data with the existing exact payload oracle.
  Transport errors/timeouts establish neither allow nor deny. Check non-superuser
  status and applicable clientid/username/all ACL records, not only usernames.
* Crucially the sensor secret denial alone cannot distinguish a missing ACL
  import from no_match=deny. Pair it with sensor publish and gateway positive
  grants, target lab control, and private import/native ACL coverage. Do not
  count the old FILE-based source probe as Mnesia evidence.

Source design facts are the original fixed seed producer emqx-body.sh authz user
rules: sensor allows publish b1/sensor/${username}/# and denies all b1/secret/#;
gateway allows subscribe b1/#. They are expected permissions, not proof that an
archive contains or restores those rows. Keep existing archive SHA/source capture
binding and inspect actual imported state privately. No credential/payload output.

Consumer compatibility checked here: generated complete-native fixture with an
enabled COOKED builtin source (including max_rules=100), observed zero-row
emqx_acl/authn/JWT tables, all five readers and persisted-values scanning. A
row_count/rows discrepancy refuses. This is not an actual native producer run,
full issued FILE+DB observation, MQTT test, or real restore. The product RAW
classifier still accepts only explicit type/enable; cooked default handling in
the private consumer does not expand that product contract. Existing issued
file observer remains required for the actual lab ACL path.

No dev-d access, public guard/scanner change or commercial claim.
