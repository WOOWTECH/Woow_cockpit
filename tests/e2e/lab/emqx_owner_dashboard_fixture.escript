#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Fixed public schema with generated credentials; no broker or secret files.
main([Path]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    undefined=emqx_dashboard_schema:https_converter(undefined,#{}),
    Input=#{<<"dashboard">>=>#{<<"default_username">>=><<"fixture-schema-dashboard-user">>,
        <<"default_password">>=><<"fixture-schema-dashboard-password">>,
        <<"listeners">>=>#{<<"http">>=>#{<<"bind">>=>18083}}}},
    Cooked=hocon_tconf:check_plain(emqx_dashboard_schema,Input,#{atom_key=>true,required=>false}),
    #{dashboard:=Dashboard}=Cooked,
    <<"fixture-schema-dashboard-user">>=maps:get(default_username,Dashboard),
    false=maps:is_key(https,maps:get(listeners,Dashboard)),
    {ok,Raw}=file:read_file(Path),
    [_,T0]=binary:split(Raw, <<"Typed = fun F(V,D) when D =< 16 ->">>),
    [T1,_]=binary:split(T0, <<"<<\"5.8.9\">> =">>),
    Source="Typed = fun F(V,D) when D =< 16 ->" ++ binary_to_list(T1) ++ "{Typed,ConfigSecrets}.",
    {ok,Tokens,_}=erl_scan:string(Source),
    {ok,Exprs}=erl_parse:parse_exprs(Tokens),
    {value,{Typed,Normalize},_}=erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    Selected=#{dashboard=>maps:with([default_username,default_password,listeners],Dashboard)},
    {Plain,Metadata}=Normalize(Selected,0,[],[]),
    io:put_chars(emqx_utils_json:encode(#{config=>Typed(Plain,0),
        config_secret_wrappers=>Typed(Metadata,0)})).
