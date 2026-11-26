#!/usr/bin/env escript
%%! +S 1:1
main([Source]) ->
    true = erlang:system_info(otp_release) =:= "26",
    ok = code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    case compile:file(Source, [binary, return_errors, return_warnings]) of
        {ok, woow_e44_fixture, Beam, _Warnings} ->
            io:format("WOOWBEAM:~s:END", [base64:encode(Beam)]);
        Error ->
            io:format(standard_error, "reviewed_fixture_compiler: ~p~n", [Error]),
            halt(1)
    end.
