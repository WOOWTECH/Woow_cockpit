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
        Http = lists:member(Args, [["--http-body"],["--sql-aliases"]]),
        Sql = Args =:= ["--sql-aliases"],
        put(sql_aliases, Sql),
        put(alias_bindings, []),
        put(binding_index, 0),
        put(http_body, Http),
        %% Effective connector inventory is validation only; occurrences below
        %% still come from the ORIGINAL tree, not expanded/merged syntax.
        Doc = hocon:transform(hocon:concat(hocon:expand(Tree)), #{format => map}),
        put(document, Doc),
        put(concat_strings, []),
        Bindings = bindings(Tree, [], false, 0),
        true = length(Bindings) =< 8192,
        %% Explicit pipeline omits include and resolve entirely.
        put(phase, transform),
        put(phase, encode),
        Contract = case {Sql,Http} of
            {true,_} -> <<"emqx-hocon-sql-context-json-v1">>;
            {false,true} -> <<"emqx-hocon-http-context-json-v1">>;
            _ -> <<"emqx-hocon-context-json-v1">>
        end,
        Document0 = #{parsed => Doc, syntax_strings => Strings, string_bindings => Bindings,
                      concat_strings => lists:reverse(get(concat_strings))},
        Document = case Sql of
            true -> Document0#{alias_bindings=>lists:reverse(get(alias_bindings))};
            false -> Document0
        end,
        Hash = binary:encode_hex(crypto:hash(sha256, Raw), lowercase),
        Out = jsone:encode(#{contract => Contract, version => <<"5.8.9">>,
            input_sha256 => Hash, input_bytes => byte_size(Raw), complete => true,
            resolution => <<"disabled">>, references => [],
            document => Document}),
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
%% Count configuration containers, not the parser's boxes/list/field plumbing.
%% A single nested object includes a box, a field tuple and often concat lists.
%% Charging each wrapper rejects ordinary auth/connector nesting as depth >32.
leaves(#{'$hcTyp' := T, '$hcVal' := V}, D) when T =:= object; T =:= array ->
    leaves(V, D+1);
leaves(#{'$hcVal' := V}, D) -> leaves(V, D);
leaves({keypath, V}, D) -> leaves(V, D);
leaves({#{'$hcTyp' := key} = K,V}, D) ->
    Keys = leaves(K,D),
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
    Keys ++ leaves(V,D);
leaves({K,V}, D) -> leaves(K,D) ++ leaves(V,D);
leaves(V, _) when is_binary(V) -> [V];
leaves(V, D) when is_list(V) ->
    case io_lib:printable_unicode_list(V) andalso V =/= [] of
        true -> [unicode:characters_to_binary(V)];
        false -> lists:append([leaves(X,D) || X <- V])
    end;
leaves(_, _) -> [].

%% Original syntax, BEFORE expand/concat/transform. No duplicate is collapsed.
bindings(_, _, _, D) when D > 32 -> throw(depth);
bindings(#{'$hcTyp' := T}, _, _, _) when T =:= include; T =:= variable -> throw(reference);
bindings(#{'$hcTyp' := object, '$hcVal' := Fields}, P, Parent, D) ->
    Action = case P of
        [<<"rule_engine">>,<<"rules">>,R,<<"actions">>,I] when is_binary(R), byte_size(R)>0, is_integer(I) ->
            field(Fields, <<"function">>) =:= [<<"republish">>];
        _ -> case Parent of {A,_,_,_} -> A; _ -> false end
    end,
    File = case P of
        [<<"authorization">>,<<"sources">>,I2] when is_integer(I2) ->
            field(Fields, <<"type">>) =:= [<<"file">>];
        _ -> false
    end,
    Http = case {get(http_body), P} of
        {true, [<<"actions">>,<<"http">>,Id]} when is_binary(Id), byte_size(Id)>0 ->
            case field(Fields, <<"connector">>) of
                [Name] when is_binary(Name) ->
                    Connectors = maps:get(<<"http">>,maps:get(<<"connectors">>,get(document),#{}),#{}),
                    Connector = maps:get(Name,Connectors,#{}),
                    re:run(Name,<<"^[A-Za-z0-9_-]+$">>,[{capture,none}]) =:= match
                        andalso is_map(Connector) andalso map_size(Connector)>0;
                _ -> false
            end;
        _ -> case Parent of {_,_,H,_} -> H; _ -> false end
    end,
    Alias = case {get(sql_aliases),P} of
        {true,[<<"rule_engine">>,<<"rules">>,Rid]} -> rule_aliases(Fields,Rid,P);
        _ -> case Parent of {_,_,_,Al} -> Al; _ -> none end
    end,
    lists:append([begin
        Parts = keyparts(K),
        Q = P ++ Parts,
        Keys = [emit(X,Q,<<"key">>,none) || X <- leaves(K,0)],
        Keys ++ bindings(V,Q,{Action,File,Http,Alias},D+1)
    end || {K,V} <- Fields]);
bindings(#{'$hcTyp' := array, '$hcVal' := Items}, P, C, D) ->
    Al = case C of {_,_,_,A} -> A; _ -> none end,
    lists:append([bindings(V,P++[I],{false,false,false,Al},D+1) || {I,V} <- lists:zip(lists:seq(0,length(Items)-1),Items)]);
bindings(#{'$hcTyp' := concat, '$hcVal' := Items} = Concat, P, C, D) ->
    %% A concat cannot grant context to components of separately merged objects.
    case Items of
        [Only] -> bindings(Only,P,C,D);
        _ ->
            Ss = leaves(Items,0),
            true = lists:all(fun(X) -> binary:match(X,<<"$">>) =:= nomatch end,Ss),
            case lists:all(fun(X) -> maps:get('$hcTyp',X) =:= string end,Items) of
                true ->
                    Wrapper = #{'$hcTyp'=>object,'$hcVal'=>[
                        {#{'$hcTyp'=>key,'$hcVal'=><<"value">>},Concat}]},
                    #{<<"value">> := Joined} = hocon:transform(hocon:concat(Wrapper),#{format=>map}),
                    true = is_binary(Joined),
                    put(concat_strings,[Joined|get(concat_strings)]);
                false -> ok
            end,
            lists:append([bindings(X,P,false,D) || X <- Items])
    end;
bindings(#{'$hcVal' := V}, P, C, D) -> bindings(V,P,C,D);
bindings(V, P, C, _) when is_binary(V) ->
    Role = case {P,C} of
        {[<<"actions">>,<<"http">>,Id,<<"parameters">>,<<"body">>], {_,_,true,_}}
          when is_binary(Id), byte_size(Id)>0 -> <<"http-body-value">>;
        {[<<"rule_engine">>,<<"rules">>,R,<<"actions">>,I], _}
          when is_binary(R), byte_size(R)>0, is_integer(I) -> <<"action-reference">>;
        {[<<"rule_engine">>,<<"rules">>,R,<<"actions">>,I,<<"args">>,F], {true,_,_,_}}
          when is_binary(R), is_integer(I), (F=:=<<"payload">> orelse F=:=<<"topic">> orelse F=:=<<"qos">> orelse F=:=<<"retain">>) -> <<"republish-value">>;
        {[<<"authorization">>,<<"sources">>,I,<<"path">>], {_,true,_,_}} when is_integer(I) -> <<"vendor-path">>;
        _ -> <<"value">>
    end,
    Alias = case C of {_,_,_,Al} -> Al; _ -> none end,
    [emit(V,P,Role,Alias)];
bindings(V,P,C,D) when is_list(V) ->
    case io_lib:printable_unicode_list(V) andalso V =/= [] of
        true -> bindings(unicode:characters_to_binary(V),P,C,D);
        false -> lists:append([bindings(X,P,C,D) || X <- V])
    end;
bindings(_,_,_,_) -> [].
keyparts(#{'$hcVal':={keypath,Parts}}) -> Parts;
keyparts(#{'$hcVal':=Part}) when is_binary(Part) -> [Part].
field(Fields, Name) ->
    case [V || {K,V} <- Fields, keyparts(K) =:= [Name]] of
        [#{'$hcTyp':=concat,'$hcVal':=[#{'$hcTyp':=string,'$hcVal':=V}]}] -> [V];
        _ -> []
    end.

%% Parse-only authority; never rule runtime, SQL evaluator or action execution.
emit(V,P,Role,Alias) ->
    I=get(binding_index), put(binding_index,I+1),
    case {Role,Alias} of
        {<<"republish-value">>,{Rule,Hash,Names}} when map_size(Names)>0 ->
            Receipt=#{binding_index=>I,rule_path=>Rule,sql_sha256=>Hash,aliases=>Names},
            put(alias_bindings,[Receipt|get(alias_bindings)]);
        _ -> ok
    end,
    #{path=>P,role=>Role,value=>V}.
rule_aliases(Fields,Rid,Path) ->
    try
        [Sql]=field(Fields,<<"sql">>), true=byte_size(Sql)=<65536,
        Rules=maps:get(<<"rules">>,maps:get(<<"rule_engine">>,get(document))),
        Sql=maps:get(<<"sql">>,maps:get(Rid,Rules)),
        {ok,Ast}=emqx_rule_sqlparser:parse(Sql),
        false=emqx_rule_sqlparser:select_is_foreach(Ast),
        Fs=emqx_rule_sqlparser:select_fields(Ast), true=length(Fs)=<64,
        Targets=[target(F)||F<-Fs,F=/='*'],
        true=length(Targets)=:=length(lists:usort(Targets)),
        Pairs=[{N,Source} || {as,Expr,{var,N}}<-Fs,
                            valid_alias(N), {ok,Source}<-[pure_source(Expr)]],
        Names=maps:from_list(Pairs),
        Hash=binary:encode_hex(crypto:hash(sha256,Sql),lowercase),
        {Path,Hash,Names}
    catch _:_ -> none end.
target({as,_,{var,N}})->N;
target({var,N})->N;
target({path,[{key,N}|_]})->N;
target(_)->throw(unsupported_target).
valid_alias(N) when is_binary(N) ->
    re:run(N,<<"^[A-Za-z_][A-Za-z0-9_]*$">>,[{capture,none}])=:=match
    andalso not lists:member(string:lowercase(N),
        [<<"env">>,<<"file">>,<<"vault">>,<<"include">>,<<"home">>,<<"emqx_etc_dir">>,<<"os">>,<<"system">>])
    andalso not lists:member(N,scalar_roots()++map_roots()++[<<"metadata">>]);
valid_alias(_)->false.
pure_source({var,N})->pure_path([N]);
pure_source({path,Parts})->
    case lists:all(fun({key,K})->is_binary(K);(_)->false end,Parts) of
        true->pure_path([K||{key,K}<-Parts]);false->error
    end;
pure_source(_)->error.
pure_path(P) when length(P)>0,length(P)=<16 ->
    case lists:all(fun(K)->re:run(K,<<"^[A-Za-z_][A-Za-z0-9_]*$">>,[{capture,none}])=:=match end,P)
         andalso (lists:member(hd(P),map_roots()) orelse
                  (length(P)=:=1 andalso lists:member(hd(P),scalar_roots())) orelse
                  P=:=[<<"metadata">>,<<"rule_id">>]) of
        true->{ok,P};false->error
    end;
pure_path(_)->error.
map_roots()->[<<"payload">>,<<"flags">>,<<"headers">>,<<"pub_props">>,<<"client_attrs">>].
scalar_roots()->[<<"topic">>,<<"clientid">>,<<"username">>,<<"qos">>,<<"retain">>,
    <<"id">>,<<"peerhost">>,<<"peername">>,<<"publish_received_at">>,
    <<"event">>,<<"timestamp">>,<<"node">>].
