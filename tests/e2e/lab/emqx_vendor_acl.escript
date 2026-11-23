#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
%% Fixed pinned-image observation only. No argv-selected paths or env resolution.
main([]) ->
    try
        lists:foreach(fun(P) ->
            {ok, I} = file:read_link_info(P), directory = element(3, I)
        end, ["/opt", "/opt/emqx", "/opt/emqx/etc"]),
        Path = "/opt/emqx/etc/acl.conf",
        {ok, Before} = file:read_link_info(Path),
        regular = element(3, Before),
        Size = element(2, Before), true = Size > 0 andalso Size =< 65536,
        {ok, Raw} = file:read_file(Path),
        true = byte_size(Raw) =:= Size,
        {ok, Before} = file:read_link_info(Path),
        code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
        {ok, Tokens, _} = erl_scan:string(unicode:characters_to_list(Raw)),
        true = length(Tokens) =< 16384,
        Terms = terms(Tokens, [], []), true = Terms =/= [],
        Out = jsone:encode(#{contract => <<"emqx-vendor-acl-v1">>,
            content_b64 => base64:encode(Raw), terms => Terms}),
        true = byte_size(Out) =< 1048576,
        io:put_chars(Out)
    catch _:_ -> halt(2)
    end;
main(_) -> halt(2).

%% Parse every term through EOF. No eval, consult-selected paths, or execution.
terms([], [], Acc) -> lists:reverse(Acc);
terms([T|Rest], Pending, Acc) ->
    case element(1,T) of
        dot -> {ok, Value} = erl_parse:parse_term(lists:reverse([T|Pending])),
               terms(Rest, [], [typed(Value,0)|Acc]);
        _ -> terms(Rest, [T|Pending], Acc)
    end;
terms(_, _, _) -> throw(incomplete).

typed(_, D) when D > 16 -> throw(depth);
typed(V, _) when is_binary(V) -> #{type => <<"binary">>, value => base64:encode(V)};
typed(V, _) when is_atom(V) -> #{type => <<"atom">>, value => atom_to_binary(V, utf8)};
typed(V, _) when is_integer(V) -> #{type => <<"integer">>, value => V};
typed(V, _) when is_float(V) -> #{type => <<"float">>, value => V};
typed(V, D) when is_tuple(V) ->
    #{type => <<"tuple">>, value => [typed(X,D+1) || X <- tuple_to_list(V)]};
typed(V, D) when is_list(V) ->
    #{type => <<"list">>, value => [typed(X,D+1) || X <- V]};
typed(V, D) when is_map(V) ->
    #{type => <<"map">>, value => [[typed(K,D+1),typed(X,D+1)] || {K,X} <- maps:to_list(V)]};
typed(_, _) -> throw(unsupported).
