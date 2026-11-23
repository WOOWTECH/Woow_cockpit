#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Offline public-source policy fixture; no broker, backend module or lab calls.
main([Path]) ->
    {ok,Raw} = file:read_file(Path),
    [_,Tail] = binary:split(Raw, <<"StoragePolicy = fun(Storage) ->">>),
    [Body,_] = binary:split(Tail, <<"put(woow_target_stage, typed_setup),">>),
    Source = "StoragePolicy = fun(Storage) ->" ++ binary_to_list(Body) ++ "{StoragePolicy,StorageReceipt}.",
    {ok,Tokens,_} = erl_scan:string(Source),
    {ok,Exprs} = erl_parse:parse_exprs(Tokens),
    {value,{Policy,Receipt},_} = erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    lists:foreach(fun(S) -> ok = Policy(S) end,
        [ram_copies,disc_copies,disc_only_copies,
         {ext,rocksdb_copies,mnesia_rocksdb},
         {ext,null_copies,mria_mnesia_null_storage}]),
    lists:foreach(fun(S) ->
        put(fold_entered,false),
        Refused = try Policy(S), put(fold_entered,true), false catch error:_ -> true end,
        true = Refused, false = get(fold_entered)
    end,[null_copies,unknown,{ext,custom,mnesia_rocksdb},
         {ext,rocksdb_copies,custom},{ext,null_copies,mnesia_rocksdb},
         {ext,rocksdb_copies,mria_mnesia_null_storage},
         {ext,custom,mria_mnesia_null_storage},{ext,null_copies,custom}]),
    Null = {ext,null_copies,mria_mnesia_null_storage},
    ok = Receipt(Null,0,0,0,0),
    lists:foreach(fun({C,N,N2,After}) ->
        storage_null_nonempty = try Receipt(Null,C,N,N2,After), accepted
                               catch error:R -> R end
    end,[{1,0,0,0},{0,1,0,0},{0,0,1,0},{0,0,0,1},{false,0,0,0}]),
    ok = Receipt({ext,rocksdb_copies,mnesia_rocksdb},2,2,2,2),
    io:format("OWNERSTORAGEFIXTUREOK").
