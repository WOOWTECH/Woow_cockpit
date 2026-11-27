#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
%% Owner executes in a disposable bounded VM on OWNER-CREATED checkpoint only.
main(["--owner-created-checkpoint", Table, Input, Output]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    Dir = filename:dirname(escript:script_name()),
    try
        {ok,emqx_mnesia_checkpoint,Bin} = compile:file(
            filename:join(Dir,"emqx_mnesia_checkpoint.erl"),[binary,return_errors]),
        {module,emqx_mnesia_checkpoint} = code:load_binary(emqx_mnesia_checkpoint,"trusted-local-exporter",Bin),
        ok = emqx_mnesia_checkpoint:export_owned(Table,Input,Output)
    catch _:_ -> halt(2) end;
main(_) -> halt(2).
