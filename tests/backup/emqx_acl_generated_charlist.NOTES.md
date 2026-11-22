Exact imported generated ACL charlist and serialization-free disable

Primary source checkout a8319fe:
* emqx_auth/src/emqx_authz/sources/emqx_authz_file.erl:61-75 exports file contents
  as rules, and on import write_files writes rules then maps:put(path,AclPath).
* Same file:120-121 acl_conf_file() is filename:join([emqx:data_dir(),"authz","acl.conf"]),
  a native charlist with the configured candidate data_dir string.
* emqx_utils/src/emqx_utils_json.erl:63-68,126-127 keeps lists recursively as
  JSON arrays through jiffy:encode; it does not coerce charlists to UTF8 strings.
* emqx_authz_file_schema.erl:39-47 path type is string() with native file validator.
* emqx_authz.erl:656-665 import uses emqx_conf:update([authorization],RawMap,
  #{override_to=>cluster}); lines224-239 root replacement invokes source replacement.

This establishes a concrete way for the imported raw path to appear as an integer
array. Actual ARM14 only proved nontext, not this exact array. Unknown shapes
still refuse with fixed side/type/enable stages; no raw values are emitted.

Support is imported-only for EXACT ASCII int(not bool) array spelling
/opt/emqx/data/authz/acl.conf, and only when original AND imported node.data_dir
are exactly /opt/emqx/data. Product target_broker mounts its own invocation-created
emqx-new volume at DATA_TARGET=/opt/emqx/data. No caller-selected path, generic
array/string conversion, character normalization, relative-path inference or
missing-context default is permitted. Original target admission is unchanged.

For this array case only, the intermediate is updated using a fixed constant
VM-side expression. It revalidates fixed data_dir, exactly file+builtin sources,
exact generated native charlist, builtin raw two-key/enable=true, then reads and
updates the existing native authorization map, flipping just enable=false.
It prints only fixed OK/REFUSED, timeout10s/output256B, fixed emqx-new role.
No interpolated Erlang terms, eval of data, Python file reads or new observer/path
exceptions. Native schema validation may reread the already active candidate ACL
as part of normal emqx_conf:update; this patch does not bypass that validation.

Full Python expected raw intermediate stays an integer array and must read back
exactly before/after the second ACL receipt. Final target settings still use the
existing JSON restore with original target string path, strict/full readback and
third ACL receipt. Existing rows/schema digest and count gates remain unchanged.
Other string cases keep the prior intermediate JSON path; no broad update mode.

Host-only model tests verify sequence, raw-array retention, final absolute policy,
all three receipts, and fail closed on normalization, same-count mutation, wrong
array/values/context, native refusal. This increment did NOT execute native/lab
code, so exact runtime API/backend compatibility remains for main's actual test.
It avoids requiring a new JSON-array -> HOCON path roundtrip, whose native success
has not been proved here. It does not claim native acceptance from model tests.
