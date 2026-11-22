#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
main([Path]) ->
    %% Only our fixed public expression source; never config/checkpoint input.
    {ok,Raw} = file:read_file(Path),
    case erl_scan:string(unicode:characters_to_list(Raw)) of
        {ok,Tokens,_} ->
            case erl_parse:parse_exprs(Tokens) of
                {ok,_} -> io:format("OWNERPARSEOK");
                {error,{Loc,Module,Reason}} ->
                    io:format("OWNERPARSEFAIL:~p:~ts",[Loc,Module:format_error(Reason)]),halt(2)
            end;
        _ -> io:format("OWNERPARSEFAIL:scanner"),halt(2)
    end.
