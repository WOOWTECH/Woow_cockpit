#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
-mode(compile).
-export([roots/0,fields/1]).
roots() -> [{authorization,hoconsc:mk(hoconsc:ref(emqx_authz_schema,"authorization"))}].
fields(_) -> [].
main([]) -> try run() catch _:_ -> io:put_chars("FIXED_MNESIA_ACL_COMPONENTS_REFUSED"),halt(1) end.
run() ->
    _FixedAtoms=[authorization,no_match,deny_action,sources,type,file,enable,path,built_in_database,cache,max_size,ttl,excludes,max_rules],
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    emqx_authz_schema:injected_fields([emqx_authz_file_schema,emqx_authz_mnesia_schema]),
    {ok,B}=file:read_file("/input/authorization.conf"),
    {ok,Raw}=hocon:binary(B,#{format=>map}),
    #{authorization:=#{no_match:=deny,sources:=[#{type:=file,enable:=true},
        #{type:=built_in_database,enable:=true}]}}=
        hocon_tconf:check_plain(?MODULE,Raw,#{atom_key=>true,required=>false}),
    File=emqx_authz_file:create(#{path=><<"/input/acl.conf">>}),
    Client=fun(U)->#{username=>U,clientid=><<"synthetic-client">>} end,
    {matched,allow}=emqx_authz_file:authorize(Client(<<"lab">>),#{action_type=>subscribe,qos=>0},<<"lab/probe">>,File),
    {matched,deny}=emqx_authz_file:authorize(Client(<<"b1-sensor">>),#{action_type=>subscribe,qos=>0},<<"b1/secret/probe">>,File),
    nomatch=emqx_authz_file:authorize(Client(<<"b1-gateway">>),#{action_type=>subscribe,qos=>0},<<"b1/retained/probe">>,File),
    application:set_env(mnesia,dir,"/work/mnesia"),
    ok=mnesia:create_schema([node()]),ok=application:start(mnesia),
    {atomic,ok}=mnesia:create_table(emqx_acl,[{attributes,[who,rules]},{ram_copies,[node()]}]),
    %% Synthetic reproduction of the source username rule; NOT imported data.
    ok=mnesia:dirty_write({emqx_acl,{1,<<"b1-gateway">>},[{allow,subscribe,<<"b1/#">>}]}),
    DB=#{type=>built_in_database},
    {matched,allow}=emqx_authz_mnesia:authorize(Client(<<"b1-gateway">>),#{action_type=>subscribe,qos=>0},<<"b1/retained/probe">>,DB),
    nomatch=emqx_authz_mnesia:authorize(Client(<<"b1-gateway">>),#{action_type=>subscribe,qos=>0},<<"outside/probe">>,DB),
    nomatch=emqx_authz_mnesia:authorize(Client(<<"unknown">>),#{action_type=>subscribe,qos=>0},<<"b1/retained/probe">>,DB),
    ok=mnesia:dirty_delete(emqx_acl,{1,<<"b1-gateway">>}),
    nomatch=emqx_authz_mnesia:authorize(Client(<<"b1-gateway">>),#{action_type=>subscribe,qos=>0},<<"b1/retained/probe">>,DB),
    ok=application:stop(mnesia),
    io:put_chars("FIXED_MNESIA_ACL_COMPONENTS_PASS").
