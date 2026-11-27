#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
%% SYNTHETIC ONLY. Creates a fresh native DB under caller-provided empty /work.
main([Table, Scenario]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    Dir = filename:dirname(escript:script_name()),
    {ok,emqx_mnesia_checkpoint,Bin} = compile:file(
        filename:join(Dir,"emqx_mnesia_checkpoint.erl"),[binary,return_errors]),
    {module,emqx_mnesia_checkpoint} = code:load_binary(emqx_mnesia_checkpoint,"trusted-fixture",Bin),
    {Tab,Record,Attrs} = emqx_mnesia_checkpoint:layout(Table),
    application:set_env(mnesia,dir,"/work/db"),
    ok = mnesia:create_schema([node()]),
    ok = mnesia:start(),
    Type = case Tab of emqx_authn_mnesia -> ordered_set;
                       emqx_authn_scram_mnesia -> ordered_set;
                       emqx_acl -> ordered_set; _ -> set end,
    {atomic,ok} = mnesia:create_table(Tab,[{type,Type},{record_name,Record},
                                {attributes,Attrs},{disc_copies,[node()]}]),
    ok = mnesia:wait_for_tables([Tab],5000),
    Value = case Scenario of
        "fun" -> fun() -> synthetic_only end;
        "pid" -> self();
        "ref" -> make_ref();
        "port" -> hd(erlang:ports());
        "improper" -> [1|2];
        "float" -> 1.5;
        "huge_integer" -> 1 bsl 100;
        "deep" -> lists:foldl(fun(_,Acc)->[Acc] end,<<"nested">>,lists:seq(1,20));
        "oversize" -> binary:copy(<<"x">>,65537);
        _ -> #{<<"fixture-map-key">> => [<<"fixture-private-binary">>,
                      "fixture-private-charlist", synthetic_atom, 42, {<<"nested">>,true}]}
    end,
    Row = list_to_tuple([Record,<<"fixture-user">>|lists:duplicate(length(Attrs)-1,Value)]),
    case Scenario of "empty" -> ok;
                     _ -> ok = mnesia:dirty_write(Tab,Row) end,
    {ok,fixture_checkpoint,[Node]} = mnesia:activate_checkpoint(
        [{name,fixture_checkpoint},{min,[Tab]},{allow_remote,false}]),
    Node = node(),
    Input = "/work/source.checkpoint",
    ok = mnesia:backup_checkpoint(fixture_checkpoint,Input),
    ok = mnesia:deactivate_checkpoint(fixture_checkpoint),
    stopped = mnesia:stop(),
    ok = file:change_mode(Input,8#600),
    case lists:member(Scenario,["wrong_schema","extra_schema","late_unknown","duplicate_schema"]) of
        true ->
            Alter = fun(Item, Acc) ->
                case {Scenario,Item} of
                    {"wrong_schema",{schema,Tab,Props}} ->
                        {[{schema,Tab,lists:keyreplace(attributes,1,Props,{attributes,[wrong]})}],Acc};
                    {"extra_schema",{schema,Tab,Props}} ->
                        {[Item,{schema,other_table,Props}],Acc};
                    {"duplicate_schema",{schema,Tab,_}} -> {[Item,Item],Acc};
                    {"late_unknown",T} when is_tuple(T), element(1,T) =:= Tab ->
                        {[Item,{unknown_table,<<"late-private">>}],Acc};
                    _ -> {[Item],Acc}
                end
            end,
            {ok,[]} = mnesia:traverse_backup(Input,mnesia_backup,"/work/changed.checkpoint",mnesia_backup,Alter,[]),
            ok = file:rename("/work/changed.checkpoint",Input);
        false -> ok
    end,
    case Scenario of
        "truncated" -> {ok,B} = file:read_file(Input),
                       ok = file:write_file(Input,binary:part(B,0,byte_size(B)-17));
        "trailing" -> {ok,Fd} = file:open(Input,[append,binary]),
                      ok = file:write(Fd,<<"non-log-trailer">>), ok = file:close(Fd);
        _ -> ok
    end,
    ok = file:change_mode(Input,8#600),
    %% Synthetic entrypoint records no private payload in stdout/stderr.
    case emqx_mnesia_checkpoint:export_owned(Table,Input,"/work/export.json") of
        ok -> halt(0);
        {error,checkpoint_export_refused} -> halt(2)
    end.
