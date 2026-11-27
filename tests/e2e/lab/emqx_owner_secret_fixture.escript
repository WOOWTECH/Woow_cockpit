#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Local cached public image only; no broker, loader or credential-file access.
main([Path]) ->
    true = code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")) =:= ok,
    {ok,Raw} = file:read_file(Path),
    [_,T0] = binary:split(Raw, <<"Typed = fun F(V,D) when D =< 16 ->">>),
    [T1,_] = binary:split(T0, <<"<<\"5.8.9\">> =">>),
    Source = "Typed = fun F(V,D) when D =< 16 ->" ++ binary_to_list(T1) ++
        "{Typed,ConfigSecrets}.",
    {ok,Tokens,_} = erl_scan:string(Source),
    {ok,Exprs} = erl_parse:parse_exprs(Tokens),
    {value,{Typed,Normalize},_} = erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    Secret = <<"fixture-native-wrapped-secret-private">>,
    Wrapped = emqx_secret:wrap(Secret),
    Input = #{dashboard => #{default_password => Wrapped}},
    {Plain,Metadata} = Normalize(Input,0,[],[]),
    #{dashboard := #{default_password := Secret}} = Plain,
    [#{env := [Secret],path := [{map,dashboard},{map,default_password}]}] = Metadata,
    {Plain,Metadata} = Normalize(Input,0,[],[]),
    %% Typed remains data-only, including in schema/row/provider contexts.
    unsupported_function = try Typed(Wrapped,0), accepted catch error:R0 -> R0 end,
    NeverCall = fun() -> put(arbitrary_fun_executed,true), Secret end,
    NeverCall1 = fun(_) -> put(arbitrary_fun_executed,true) end,
    Adversarial = [NeverCall,NeverCall1,fun erlang:node/0,
        emqx_secret:wrap_load({file,<<"/never-read-this-file">>}),
        emqx_secret:wrap(NeverCall),emqx_secret:wrap(Wrapped),
        emqx_secret:wrap(#{secret => Secret}),emqx_secret:wrap([Secret]),
        emqx_secret:wrap(self()),emqx_secret:wrap(make_ref()),
        emqx_secret:wrap(binary:copy(<<0>>,65537))],
    lists:foreach(fun(V) ->
        unsupported_function = try Normalize(#{nested => [V]},0,[],[]), accepted
                               catch error:R -> R end
    end,Adversarial),
    undefined = get(arbitrary_fun_executed),
    lists:foreach(fun(V) ->
        Refused = try Normalize(V,0,[],[]), false catch error:_ -> true end,
        true = Refused
    end,[self(),make_ref(),lists:duplicate(129,Wrapped),
         lists:foldl(fun(_,A) -> [A] end,Wrapped,lists:seq(1,17))]),
    {ok,AllTokens,_} = erl_scan:string(unicode:characters_to_list(Raw)),
    {ok,_} = erl_parse:parse_exprs(AllTokens),
    %% Synthetic private reply for the Python contract/scan integration test.
    io:format("~s",[emqx_utils_json:encode(#{config => Typed(Plain,0),
        config_secret_wrappers => Typed(Metadata,0)})]).
