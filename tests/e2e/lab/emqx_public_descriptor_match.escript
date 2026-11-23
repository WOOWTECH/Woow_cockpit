#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Match a code-only SHA against immutable cached-image exports. Never load,
%% execute or call module_info/on_load of any catalogue module. Paths are fixed.
main([HashString]) ->
    64 = length(HashString),
    true = lists:all(fun(C) -> (C >= $0 andalso C =< $9) orelse (C >= $A andalso C =< $F) end,HashString),
    Wanted = list_to_binary(HashString),
    Files = filelib:wildcard("/opt/emqx/lib/*/ebin/*.beam"),
    true = length(Files) > 0,
    Matches = lists:flatmap(fun(Path) ->
        {ok,Beam} = file:read_file(Path),
        {ok,{Mod,[{exports,Exports}]}} = beam_lib:chunks(Beam,[exports]),
        {ok,{Mod,Md5}} = beam_lib:md5(Beam),
        [#{module => atom_to_list(Mod),name => atom_to_list(Name),arity => Arity,
           type => external,md5 => binary_to_list(binary:encode_hex(Md5)),
           descriptor_sha256 => HashString,public_beam => Path} || {Name,Arity} <- Exports,
           binary:encode_hex(crypto:hash(sha256,term_to_binary({Mod,Name,Arity,external}))) =:= Wanted]
    end,Files),
    lists:foreach(fun(M) ->
        io:format("MATCH:~s:~s:~B:~s:~s:END~n",[
            base64:encode(maps:get(module,M)),base64:encode(maps:get(name,M)),
            maps:get(arity,M),maps:get(md5,M),base64:encode(maps:get(public_beam,M))])
    end,Matches),
    io:format("MATCHDONE").
