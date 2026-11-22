#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
%% Trusted EMQX 5.8.9 / hocon 0.44.0 only. Never load archive code/ETF.
main(Args) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    put(phase, input),
    try
        {ok, Raw} = file:read_file("/input/source.hocon"),
        true = byte_size(Raw) =< 8388608,
        put(phase, tokenize),
        Tokens = hocon_token:scan(Raw, #{}),
        true = length(Tokens) =< 32768,
        put(phase, references),
        lists:foreach(fun(T) ->
            case element(1,T) of include -> throw(reference); variable -> throw(reference); _ -> ok end
        end, Tokens),
        put(phase, parse),
        Tree = hocon_token:parse(hocon_token:trans_key(hocon_token:rm_trailing_comma(Tokens)), #{}),
        put(phase, syntax),
        Strings = leaves(Tree, 0),
        %% Explicit pipeline omits include and resolve entirely.
        put(phase, transform),
        Doc = hocon:transform(hocon:concat(hocon:expand(Tree)), #{format => map}),
        put(phase, encode),
        Hash = binary:encode_hex(crypto:hash(sha256, Raw), lowercase),
        Out = jsone:encode(#{contract => <<"emqx-hocon-json-v1">>, version => <<"5.8.9">>,
            input_sha256 => Hash, input_bytes => byte_size(Raw), complete => true,
            resolution => <<"disabled">>, references => [],
            document => #{parsed => Doc, syntax_strings => Strings}}),
        true = byte_size(Out) =< 1048576,
        io:put_chars(Out)
    catch Class:Reason ->
        case Args of
            ["--diagnose"] ->
                Phase = case {Class,Reason} of
                    {throw,file_dependency} -> file_dependency;
                    {throw,reference} -> reference;
                    _ -> get(phase)
                end,
                io:put_chars(jsone:encode(#{contract => <<"emqx-hocon-diagnostic-v1">>,
                    phase => Phase, result => <<"refused">>}));
            _ -> ok
        end,
        halt(2)
    end.

%% Retain overwritten and concatenated string components as well as effective map.
%% Reject reference nodes again on the parsed AST; no file/env resolution APIs.
leaves(_, D) when D > 32 -> throw(depth);
leaves(#{'$hcTyp' := T}, _) when T =:= include; T =:= variable -> throw(reference);
leaves(#{'$hcVal' := V}, D) -> leaves(V, D+1);
leaves({keypath, V}, D) -> leaves(V, D+1);
leaves({#{'$hcTyp' := key} = K,V}, D) ->
    Keys = leaves(K,D+1),
    lists:foreach(fun(Key) ->
        Parts = binary:split(Key, <<".">>, [global]),
        lists:foreach(fun(Part) ->
            case lists:member(Part, [<<"certfile">>, <<"keyfile">>, <<"cacertfile">>,
                                    <<"bootstrap_file">>, <<"init_file">>])
                 orelse lists:suffix("_file", binary_to_list(Part)) of
                true -> throw(file_dependency); false -> ok
            end
        end, Parts)
    end, Keys),
    Keys ++ leaves(V,D+1);
leaves({K,V}, D) -> leaves(K,D+1) ++ leaves(V,D+1);
leaves(V, _) when is_binary(V) -> [V];
leaves(V, D) when is_list(V) ->
    case io_lib:printable_unicode_list(V) andalso V =/= [] of
        true -> [unicode:characters_to_binary(V)];
        false -> lists:append([leaves(X,D+1) || X <- V])
    end;
leaves(_, _) -> [].
