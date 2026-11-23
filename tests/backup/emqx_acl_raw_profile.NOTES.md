Raw authorization removal profile correction (not exact100 candidate)

Base041a6ae. Does not include37963a4: builtin raw type/enable only remains strict.
ActualARM11 reported exact_type_enable; additional fixed gate reasons are now
emitted from the same capture before every profile rejection. Reason identifiers
contain no dynamic keys, paths, values, schema bodies or counts.

Pinned source checkout a8319fe primary contract:
apps/emqx/src/emqx_schema.erl:2598-2630 declares no_match/deny_action defaults;
raw omission is not an invalid present enum. disabled_intermediate now validates
these only if present and copies omission exactly. No default values are invented.
The default read_effective_config still requires both fields. Only restore's
imported before/intermediate reads explicitly opt into omission. Final target
readback is strict, full-config exact, and target_broker STRICT check is unchanged.
This also explains why omission was not proven as ARM11's cause: the old default
reader would already reject it before acl_profile.

emqx_schema.erl:350-390 declares cache enable(bool), max_size(range1..1048576),
ttl(duration), excludes(array(binary)). The profile preserves valid nonempty
string topic-filter excludes rather than inventing an empty-only restriction.
It does not execute or resolve excludes as files/loaders. Existing raw TTL subset
is unchanged. node_cache is not declared by this checkout's authz root or schema;
it remains unknown/refused. There is no arbitrary-field dropping or bypass.

Fixed reasons: auth_shape/auth_unknownfields/auth_no_match/auth_deny_action,
sources_shape,builtin_duplicate/builtin_shape,cache_shape/cache_unknownfields/
cache_enable/cache_max_size/cache_ttl/cache_excludes,source_shape/source_duplicate/
source_type,file_fields/file_enable/file_path. Enabled builtin removal still
requires exact two-key source and all old native row/schema receipt checks.

Host-only tests cover actual candidate entry, omitted keys in loaded intermediate,
full final explicit restore, strict default reader, invalid present enums and all
fixed profile refusal classes. No lab/native execution or workflow edits. No
claim that this resolves ARM11 until actualfixedreason or next runtime proof.
