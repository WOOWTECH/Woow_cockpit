#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
-mode(compile).
-export([roots/0,fields/1]).
%% Same public schema entrypoint as emqx_mnesia_acl_target_fixture.escript.
roots() -> [{authorization,hoconsc:mk(hoconsc:ref(emqx_authz_schema,"authorization"))}].
fields(_) -> [].
main([]) ->
    try run() catch _:_ -> io:put_chars("FIXED_BUILTIN_SCHEMA_REFUSED"),halt(1) end.
run() ->
    _FixedAtoms=[authorization,no_match,deny_action,sources,type,enable,
        built_in_database,cache,max_size,ttl,excludes,max_rules],
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    emqx_authz_schema:injected_fields([emqx_authz_mnesia_schema]),
    lists:foreach(fun(Enabled)->
        Source=#{<<"type">>=><<"built_in_database">>,<<"enable">>=>Enabled},
        Raw=#{<<"authorization">>=>#{<<"no_match">>=><<"deny">>,<<"sources">>=>[Source]}},
        #{authorization:=#{no_match:=deny,sources:=[Checked]}}=
            hocon_tconf:check_plain(?MODULE,Raw,#{atom_key=>true,required=>false}),
        #{type:=built_in_database,enable:=Enabled}=Checked,
        %% Explicitly observe the native default; Python intentionally refuses
        %% expanded objects rather than silently dropping this extra key.
        100=maps:get(max_rules,Checked),
        false=maps:is_key(path,Checked),false=maps:is_key(url,Checked),
        false=maps:is_key(loader,Checked)
    end,[true,false]),
    io:put_chars("FIXED_BUILTIN_SCHEMA_PASS").
