HOLD: isolated candidate pending main's actual exact-profile observation

Do not integrate solely on schema default knowledge. Adoption is authorized by
main only after actual target/imported raw profile reports precisely
exact_type_enable_maxrules100. This branch does not deploy or run a broker.

Primary pinned public source checkout a8319fe:
apps/emqx_auth_mnesia/src/emqx_authz_mnesia_schema.erl:35-51 declares MAX_RULES=100
and pos_integer default100. It does not restrict native values to100: rejecting
99/101 here is an intentional restricted candidate profile, not a native claim.
The previously executed pinned-image component fixture observed native default100.
This patch extends that fixture to explicit100 for both bool enable states; the
extended native fixture has NOT been executed this turn (code-only/no lab).

Candidate classifier accepts exactly:
{type:'built_in_database',enable:bool}
{type:'built_in_database',enable:bool,max_rules:int100}
No max_rules default insertion, key dropping, coercion or caller policy code.
Unknown keys, missing required keys,99,101,bool,float/string100 all refuse, even
when disabled. Source objects are not mutated. Existing fixed diagnostic enums
remain unchanged; shape observation alone is not a runtime acceptance receipt.

The same classifier is used by product target references and candidate removal.
Full raw source objects therefore retain explicit100 through target readback;
the disable intermediate changes only enable tofalse and retains max_rules100.
For a FILE-only final target the builtin source is intentionally removed in phase2;
its third field is not rewritten/dropped before removal. Tests reject intermediate
or restored target readback that silently loses max_rules.

Host tests model product entry and native-destructive removal; not HA/MQTT/native
acceptance. No count gate, digest checks, file guard, workflow or scanner changes.
