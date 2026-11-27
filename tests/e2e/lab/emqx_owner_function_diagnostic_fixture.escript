#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
main([Path]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    {module,emqx_schema} = code:ensure_loaded(emqx_schema),
    {ok,Raw} = file:read_file(Path),
    [_,T0] = binary:split(Raw, <<"Typed = fun F(V,D) when D =< 16 ->">>),
    [T1,_] = binary:split(T0, <<"<<\"5.8.9\">> =">>),
    Source = "Typed = fun F(V,D) when D =< 16 ->" ++ binary_to_list(T1) ++
        "ConfigFunctionDiagnostic.",
    {ok,Tokens,_} = erl_scan:string(Source),
    {ok,Exprs} = erl_parse:parse_exprs(Tokens),
    {value,Diagnostic,_} = erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    Secret = <<"fixture-env-value-must-never-appear">>,
    Unknown = fun() -> put(unknown_executed,true), Secret end,
    D1 = Diagnostic(emqx_secret:wrap(#{private => Secret}),[{map,default_password},{map,dashboard}]),
    D2 = Diagnostic(emqx_secret:wrap_load({file,Secret}),[{map,time_offset},{map,Secret},{map,file},{map,log}]),
    D3 = Diagnostic(fun emqx_schema:namespace/0,[{map,time_offset},{map,console},{map,log}]),
    D4 = Diagnostic(Unknown,[{map,Secret}]),
    undefined = get(unknown_executed),
    map = maps:get(env_kind,D1),
    tuple = maps:get(env_kind,D2),
    empty = maps:get(env_kind,D3),
    unknown = maps:get(module,D4),
    other_config = maps:get(path,D4),
    io:format("~s",[emqx_utils_json:encode([D1,D2,D3,D4])]).
