-module(woow_e44_fixture).
-behaviour(application).
-export([start/2, stop/1, loop/0, ping/0]).
start(_, _) ->
    Pid = spawn_link(?MODULE, loop, []),
    true = register(?MODULE, Pid),
    {ok, Pid}.
stop(_) -> ok.
loop() ->
    receive
        {ping, From, Ref} -> From ! {Ref, e44_fixture_alive}, loop();
        _ -> loop()
    end.
ping() ->
    Ref = make_ref(),
    ?MODULE ! {ping, self(), Ref},
    receive {Ref, e44_fixture_alive} -> e44_fixture_alive after 3000 -> error(fixture_not_running) end.
