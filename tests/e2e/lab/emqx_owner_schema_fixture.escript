#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Public synthetic native fixture: evaluate exact fixed producer closures.
main([Path]) ->
    {ok,Raw} = file:read_file(Path),
    [_,C0] = binary:split(Raw, <<"CanonicalSchema = fun(T,Records) ->">>),
    [C1,_] = binary:split(C0, <<"%% Fixed builtin policy:">>),
    [_,T0] = binary:split(Raw, <<"Typed = fun F(V,D) when D =< 16 ->">>),
    [T1,_] = binary:split(T0, <<"<<\"5.8.9\">> =">>),
    Source = "CanonicalSchema = fun(T,Records) ->" ++ binary_to_list(C1) ++
        "Typed = fun F(V,D) when D =< 16 ->" ++ binary_to_list(T1) ++
        "{CanonicalSchema,Typed}.",
    {ok,Tokens,_} = erl_scan:string(Source),
    {ok,Exprs} = erl_parse:parse_exprs(Tokens),
    {value,{Canonical,Typed},_} = erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    Props = [{name,schema},{type,set},{index,[3]},
             {user_properties,[{private_secret,<<"fixture-schema-secret">>}]},
             {mnesia_backend_types,[{null_copies,mria_mnesia_null_storage}]}],
    {schema,Props} = Canonical(schema,[{schema,schema,Props}]),
    _ = Typed(Canonical(schema,[{schema,schema,Props}]),0),
    lists:foreach(fun(Records) ->
        schema_record_invalid = try Canonical(schema,Records), accepted catch error:R -> R end
    end,[[],[{schema,other,Props}],[{schema,schema,Props},{schema,schema,Props}],
         [{schema,schema,[{name,schema},{name,schema}]}],[{schema,schema,[bad_property]}]]),
    lists:foreach(fun({Value,Reason}) ->
        Reason = try Typed([{schema,[{private_property,Value}]}],0), accepted catch error:R -> R end
    end,[{self(),unsupported_pid},{make_ref(),unsupported_reference},
         {fun() -> <<"private-env-never-serialized">> end,unsupported_function},
         {<<1:1>>,unsupported_bitstring}]),
    %% Parse the entire fixed expression too; never invoke its broker operations.
    {ok,AllTokens,_} = erl_scan:string(unicode:characters_to_list(Raw)),
    {ok,_} = erl_parse:parse_exprs(AllTokens),
    io:format("OWNERSCHEMAFIXTUREOK").
