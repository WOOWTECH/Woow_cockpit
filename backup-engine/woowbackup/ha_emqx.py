"""Home Assistant import, EMQX part: the WOOWTECH add-on `woow-emqx` -> this device's app `emqx` (CONTRACT section 9
"Home Assistant import"; facts phase3/facts/emqx.md). Owner: E2. HAOS parity (2026-11-25, DESIGN D0-D5, S1, S2; lane
EMQX-A): restoring HA's backup is what HAOS does, so HA's access settings come with it and what could hurt the customer is
listed in the one confirmation instead of refusing.

The add-on runs EMQX 5.8.9 as root with its data dir at /data/emqx/data (`data/emqx/data/` in the member: the Mnesia
database in `mnesia/<node name>/`, the Dashboard's `configs/cluster.hocon`, `certs/`, `authz/`) and pins its node name
in `data/emqx/node.name` (an install made before add-on 5.9.1 is `emqx@<HA host>.local`, a newer one `emqx@127.0.0.1`).
Mnesia is tied to the node name and the Podman broker's is fixed (`emqx@127.0.0.1`), so the files are never copied:
EMQX's own data export and import move the data, node-name independent, in two throwaway brokers of the live image
(network none, read-only root, labelled, the job's watchdog):

1. HA's broker: HA's staged files (never its cookie, generated configs, logs, plugins or hot patches) in a
   `noexec,nosuid,nodev` volume at /data/emqx/data, HA's node name (its host mapped to 127.0.0.1 with `--add-host`),
   root like on HA, an empty default dashboard password (nothing is created at boot). It answers the default-account
   check (admin/public still valid: a notice, a confirmation when this device's Dashboard is reachable from the network),
   the row counts, its root names, its authenticators and its effective authorization and authentication roots, the
   built-in password database's hashing (D1: `plain` rows and dead accounts are restored as they are and named in a
   notice; a hashing that no longer accepts this device's stored passwords names this device's MQTT accounts, read-only from
   its running broker), then `emqx ctl data export` of the data roots (DATA_ROOTS; never listeners, dashboard, node, log or
   other settings) and the table sets (TABLE_SETS: MQTT users, ACL rules, banned, Dashboard users, API keys, PSK, retained
   messages).
2. This device's broker (the candidate). First this device's running broker is read (target_static; a stopped one is
   started for the read and put back): its effective RAW configuration, EMQX_ETC_DIR, the override state. Its cluster.hocon
   and the data-volume files it names are snapshotted. The candidate: the live environment and secret mounts, the live
   base.hocon/acl.conf read-only, the snapshot in an otherwise empty data volume, `emqx ctl data import`; then HA's
   authentication and authorization roots are made exactly HA's (D0: identities, `no_match`, `deny_action`; the ACL file
   HA's import wrote replaces this device's: a notice, nothing written back), this device's bootstrap file stays attached to
   HA's built-in database authenticator, and every other setting root of this device (listeners, dashboard, node, log...)
   is loaded back exactly as it was. Every table must hold at least HA's rows and at most HA's plus what the empty broker
   seeded. HA's API keys replace this device's (the EMQX MCP admin must log in again).
   What could hurt the customer is a line of the ONE confirmation (haissues): settings that read this device's files or
   environment, rules that use jq, external authenticators, authorization sources and ExHook servers that receive client
   credentials (S1), no authentication at all (S2), settings EMQX could not import (E-67), a Dashboard that still uses
   admin/public (E-20, H3). The check builds the same candidate (H7), so these lines are known before anything is converted.
3. Readback: the finished candidate's configuration (a SHA-256 per root, this device's secret values redacted first)
   and the administrator tables (rows and a row-hash receipt) go into the converted backup (`import_check`); after the
   restore started the units, verify_restored reads the same from the restored broker: a difference in the accounts,
   ACL rules or keys fails the restore, which then rolls back by itself; a difference in settings only is reminded (E-90).

`woow_emqx_data` is that broker's volume without its generated configs (one holds the cookie), backups of
cluster.hocon, data exports and traces; `woow_emqx_log` is only its top folder. Versions: the add-on version maps to
the EMQX version it pins (VERSIONS); a version the table does not know or this device's version that cannot be read only
inform, the data decides (CM-01, CM-02, CM-06).
"""
import io
import hashlib
import base64
import json
import os
import re
import tarfile
import time

from . import habackup, hacommon, hatarget, ha_n8n, ha_odoo, podman, tempctr, util, ha_emqx_settings
from .errors import BackupError
from . import haissues

SLUG = 'woow-emqx'
APP_ID = 'emqx'
# Every issue id this module uses, with its level (haissues: the page names them; tests/backup/test_ha_issues.py checks).
ISSUES = {
    'emqx.no-database': 'stop',               # E-06: HA's backup has no EMQX database at all: nothing to move
    'emqx.node-gone': 'stop',                 # E-07/E-09: the node the customer chose is not in the backup
    'emqx.config-changing': 'stop',           # E-58: this device's settings kept changing while they were read
    'emqx.node-chosen': 'auto',               # E-07/E-09: which of HA's databases is used (the last written one)
    'emqx.config-reread': 'auto',             # E-58: this device's settings changed while they were read: read again
    'emqx.access-from-ha': 'auto',            # D0: authentication, authorization and no-match rule are HA's
    'emqx.version-asked': 'auto',             # E-04: the image has no version label: the running EMQX said it
    'emqx.file-secret': 'confirm',            # E-76 (S1): settings that read a file of this device as a secret
    'emqx.jq-rule': 'confirm',                # E-77 (S1): rules that use jq (it reads this device's environment)
    'emqx.external-authn': 'confirm',         # E-78 (S1): authenticators that receive every client's credentials
    'emqx.external-authz': 'confirm',         # S1 under D0: authorization sources that receive user names and topics
    'emqx.exhook': 'confirm',                 # E-79 (S1): ExHook servers receive every client's credentials
    'emqx.no-authentication': 'confirm',      # E-82 (S2): nobody has to log in to HA's broker
    'emqx.import-partial': 'confirm',         # E-67: EMQX could not import some of HA's settings
    'emqx.default-dashboard-exposed': 'confirm',  # E-20 + H3: admin/public on a Dashboard the network can reach
    'emqx.default-dashboard': 'notice',       # E-20: the Dashboard keeps HA's admin/public
    'emqx.plain-passwords': 'notice',         # E-17: HA stores MQTT passwords as clear text
    'emqx.plain-elsewhere': 'notice',         # E-18: ... for a listener's or a gateway's accounts
    'emqx.clear-rows': 'notice',              # E-19: accounts whose stored password is not in the form of their hashing
    'emqx.hashing-unreadable': 'notice',      # E-16: HA's hashing could not be read
    'emqx.accounts-reset': 'notice',          # SR-5, E-69: this device's own MQTT accounts need new passwords
    'emqx.accounts-unknown': 'notice',        # E-52: this device's MQTT accounts could not be read
    'emqx.bootstrap-lost': 'notice',          # E-48, E-49, E-61, E-68: this device's pre-created accounts may be gone
    'emqx.env-wins': 'notice',                # H1: this device's EMQX_* settings win over HA's after a restart
    'emqx.acl-replaced': 'notice',            # D3, E-75: HA's ACL file replaces this device's
    'emqx.config-differs': 'notice',          # E-60: this device's running settings differ from what its files give
    'emqx.target-file-missing': 'notice',     # E-55: a file this device's settings name is not there
    'emqx.sys-ticker': 'notice',              # E-13: the system messages of the throwaway broker could not be paused
    'emqx.receipt-unreadable': 'notice',      # E-84: the administrator tables' receipt could not be read
    'emqx.data-dir-moved': 'stop',            # E-36: this device's data directory is not the image's: HA's data would land elsewhere
    'emqx.output-dir-unusable': 'stop',       # E-35: a log or crash-dump place the candidate cannot be given safely
    'emqx.dirs-follow-device': 'auto',        # E-23, E-24, E-35: this device's own etc / log directories are the candidate's too
    'emqx.files-not-carried': 'notice',       # E-29, E-30, E-32, E-50: files the settings name that the candidate cannot carry
    'emqx.device-integrations': 'confirm',    # E-41: this device's own rules, connectors, actions, sources, bridges, gateways
    'emqx.device-routing': 'confirm',         # E-42: ... topic rewrite, topic metrics, auto-subscribe, ExHook servers
    'emqx.device-psk': 'confirm',             # E-43: ... PSK authentication
    'emqx.device-plugins': 'notice',          # E-44: ... plugins (they live in the container, not in the data)
    'emqx.durable-sessions': 'confirm',       # E-47: the messages queued for offline devices are not in HA's export
}
STATE = 'data/emqx'
DATA = 'data/emqx/data'
NODE_FILE = 'data/emqx/node.name'
PLUGINS = 'data/emqx/plugins'
STAGED = ('mnesia', 'configs/cluster.hocon', 'certs', 'authz')
HA_DATA_DIR = '/data/emqx/data'
DATA_TARGET = '/opt/emqx/data'
LOG_TARGET = '/opt/emqx/log'
WORK = '/work'
# Add-on version -> the EMQX release its Dockerfile pins (Woow_ha_emqx CHANGELOG.md, Dockerfile EMQX_VERSION).
VERSIONS = hacommon.VersionTable('EMQX', {'5.8.9': '5.8.9', '5.9.0': '5.8.9', '5.9.1': '5.8.9'})
# Retainer backend/storage/expiry belong to HA message data. Import them before
# Mnesia keep_tables; restoring target RAM settings would lose rows at packaging stop.
DATA_ROOTS = ('authentication', 'authorization', 'rule_engine', 'connectors', 'actions', 'sources', 'bridges',
              'rewrite', 'auto_subscribe', 'exhook', 'gateway', 'psk_authentication', 'topic_metrics',
              'retainer')
TABLE_SETS = ('builtin_authn', 'builtin_authz', 'banned', 'dashboard_users', 'api_keys', 'psk', 'builtin_retainer')
TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_banned_rules', 'emqx_admin',
          'emqx_app', 'emqx_psk', 'emqx_retainer_message')
# Tables a running EMQX 5.8.9 always has: one missing in HA's broker means its database did not load completely.
REQUIRED_TABLES = ('emqx_authn_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_admin', 'emqx_app')
# This device's broker: the image's etc dir (vendor rel/emqx_vars:16 + rebar.config.erl:407: "$BASE_RUNNER_ROOT_DIR/etc"
# in the tgz/docker build, exported by bin/emqx:269-273), proven in the running broker before its template is resolved.
ETC_DIR = '/opt/emqx/etc'
ETC_EXPR = 'io:format("WOOWETC:~s:END", [os:getenv("EMQX_ETC_DIR", "")]).'
# The broker's working directory: bin/emqx does `cd "$BASE_RUNNER_ROOT_DIR"` before it starts anything ("so relative paths like
# etc/ and data/ still work", vendor bin/emqx:1099-1101), so a relative path in a setting (`data/authz/acl.conf`, which the
# Dashboard writes for an ACL it edited, emqx_authz_file.erl:120-121) is relative to it.
BASE_DIR = '/opt/emqx'
DATA_PREFIX = DATA_TARGET + '/'
# Places that exist only while a broker runs, or that podman gives a read-only container as a private tmpfs.
RUNTIME_DIRS = ('/proc', '/sys', '/dev', '/run', '/tmp', '/var/tmp')
WRITABLE_DIRS = ('/tmp', '/var/tmp', '/run', '/dev/shm')
# Where the candidate may be given a scratch directory for what EMQX writes (logs, crash dumps), strictly below one of these;
# never anything of /opt/emqx itself besides its log and data volumes (bin, lib, erts-*, releases, etc, plugins ... are the
# image's own files and a mount would hide them).
SCRATCH_ROOTS = ('/var', '/mnt', '/srv', '/home', '/root', '/data', '/log', '/logs', '/opt')
SOURCE_NAMES = {'file': 'ACL 檔案', 'built_in_database': '內建資料庫', 'http': 'HTTP', 'redis': 'Redis', 'mysql': 'MySQL',
                'postgresql': 'PostgreSQL', 'mongodb': 'MongoDB', 'ldap': 'LDAP', 'client_info': '用戶端資訊'}
# The EMQX_* settings that decide who may connect and what a client may do: this device's own win over HA's after the next
# start (H1); only their names are ever kept.
ACCESS_ENV = re.compile(r'EMQX_(?:AUTHORIZATION|AUTHENTICATION)__[A-Z0-9_]{0,90}\Z')
ACCESS_ENV_LINE = re.compile(r'(EMQX_(?:AUTHORIZATION|AUTHENTICATION)__[A-Z0-9_]{0,90})=')
NOT_RUNNING = '這台的 EMQX 沒有在執行，無法讀取它的設定；請先到「應用軟體」啟動 EMQX 後再試一次。'
HOT_HINT = ('這份備份是在 EMQX 執行中製作的，內建資料庫可能只寫了一半；請先在 HA 停止 EMQX 附加元件，再重新製作備份後匯入'
            '（附加元件停止時製作的備份最可靠）。')
NODE_RE = re.compile(r'([A-Za-z][A-Za-z0-9_-]{0,63})@([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)\Z')
IPV4_RE = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z')
EXPORT_RE = re.compile(rb'exported to (/work/out/emqx-export-[0-9.-]{10,40}\.tar\.gz)')
READY_TIMEOUT = 300
MAX_HOCON = 8 * 1024 * 1024
MAX_EXPORT = 64 * 1024 ** 3   # sanity bound of one table's file in HA's export (E-64: the disk space decides, DESIGN)
DROPPED = re.compile(r'(?:configs/(?:app\.[^/]*\.config|vm\.[^/]*\.args|[^/]*\.bak)|backup/.+|trace/.+)\Z')

DEFAULT_ADMIN_EXPR = ('case emqx_dashboard_admin:check(<<"admin">>, <<"public">>) of {ok, _} -> default; '
                      '_ -> changed end.')
COUNT_EXPR = ('[{T, case catch mnesia:table_info(T, size) of N when is_integer(N) -> N; _ -> -1 end} || T <- ['
              + ', '.join(TABLES) + ']].')
SUSPEND_SYS_EXPR = ('P = whereis(emqx_sys), ok = sys:suspend(P, 5000), '
                    '{status, P, _, [_, suspended | _]} = sys:get_status(P, 5000), '
                    'P = whereis(emqx_sys), io:format("WOOWSYS:~s:suspended~n", [pid_to_list(P)]).')
TICKER_STATUS_EXPR = ('P = whereis(emqx_sys), true = (pid_to_list(P) =:= "{pid}"), '
                     '{status, P, _, [_, suspended | _]} = sys:get_status(P, 5000), ticker_unchanged.')
ROOTS_EXPR = 'emqx_config:get_root_names().'
AUTHN_EXPR = ('[{maps:get(mechanism, A, none), maps:get(backend, A, none), maps:get(enable, A, true), '
              'maps:get(name, maps:get(password_hash_algorithm, A, #{}), none), '
              'maps:get(salt_position, maps:get(password_hash_algorithm, A, #{}), none)} '
              '|| A <- emqx:get_config([authentication], [])].')
STRICT_EXPR = '{emqx:get_config([authorization, no_match]), emqx:get_config([authorization, deny_action])}.'
# D0: the authorization sources in the order EMQX asks them: `{type, enabled}` per source (types and flags only: a source
# may hold a password, none of it is read). Read from HA's broker and, after the import, from the candidate.
AUTHZ_EXPR = ('[{maps:get(type, S, none), maps:get(enable, S, true)} || S <- emqx:get_config([authorization, sources], [])].')
# SR-5 (OWNER DECISION 2026-11-24, option C): how the built-in password database (`password_based` + `built_in_database`,
# at most one per chain: emqx_authn_config.erl:298) hashes a password, every field EMQX 5.8.9 checks a stored row with
# (emqx_authn_password_hashing.erl:252-269 check_password: the name; `salt_position` for plain/md5/sha/sha256/sha512;
# `mac_fun`, `iterations`, `dk_length` for pbkdf2; bcrypt reads its rounds and salt from the stored hash). `none` for
# a field the algorithm does not have. Read from HA's broker and, read-only, from this device's running broker.
HASH_EXPR = ('[{maps:get(enable, A, true), maps:get(name, H, none), maps:get(salt_position, H, none), '
             'maps:get(mac_fun, H, none), maps:get(iterations, H, none), maps:get(dk_length, H, none)} '
             '|| A <- emqx:get_config([authentication], []), maps:get(mechanism, A, none) =:= password_based, '
             'maps:get(backend, A, none) =:= built_in_database, H <- [maps:get(password_hash_algorithm, A, #{})]].')
# The user ids of this device's built-in password database in the global chain (the chain the `authentication` root
# configures; its user group is the chain name: emqx_authn_chains.erl:1000-1008, ?GLOBAL = 'mqtt:global'): the count and
# the first ten names, base64 each. Only the table's KEYS are read (emqx_authn_mnesia.erl:65-70 user_info): never a
# password hash or salt.
USERS_EXPR = ('L = lists:sort([U || {G, U} <- mnesia:dirty_all_keys(emqx_authn_mnesia), G =:= \'mqtt:global\', '
              'is_binary(U)]), io:format("WOOWUSERS:~b:~s:END", [length(L), lists:join(",", '
              '[base64:encode(U) || U <- lists:sublist(L, 10)])]).')
# SR-5, security re-review 2026-11-24 (iteration 7): `plain` is not only possible in the global chain HASH_EXPR reads.
# An MQTT listener (`listeners.<type>.<name>.authentication`, chain '<type>:<name>': emqx_authn_config.erl:371-374,
# emqx_authn_chains.erl:1015-1021), a gateway (`gateway.<name>.authentication`, chain emqx_gateway_utils:global_chain/1,
# e.g. 'stomp:global' but 'mqtt-sn:global' for mqttsn: emqx_gateway_utils.erl:457-475) and a gateway's listener (chain
# emqx_gateway_utils:listener_chain/3 = '<gateway>:<type>:<name>': emqx_gateway_insta_sup.erl:295-307,
# emqx_gateway_utils.erl:431-434,477-478) can each have a built-in password database authenticator; all of them keep
# their rows in the one table the export carries whole (emqx_authn_mnesia.erl:105, the user group is the chain name:
# emqx_authn_chains.erl:1000-1008), and the `gateway` root itself is imported (DATA_ROOTS).
# Iteration 8: the stored form of every row. A row keeps what it was stored as: an algorithm change never re-hashes it
# (emqx_authn_mnesia.erl:130 update = create), a `hash` import or bootstrap file stores the given value and salt as
# they are (:541-542, :556-565), and a removed gateway leaves its rows behind (emqx_gateway_insta_sup.erl:394-421 unload
# deletes no chain). EMQX 5.8.9 can verify a row only in the exact form its authenticator's algorithm produces, so a row
# in any other form never logs in and may hold the password itself (what `plain` stores: emqx_passwd.erl:104):
#   md5 / sha / sha256 / sha512: hex of 32 / 40 / 64 / 128 characters (emqx_passwd.erl:106-113, 148-150; compared
#     without case, :77-79, 119-122; whatever the salt: :92-97);
#   pbkdf2: hex of twice `dk_length`, or of the MAC's own length when it is not set (sha 20, sha224 28, sha256 32,
#     sha384 48, sha512 64 bytes: :67-69, 140-158; md4, md5 and ripemd160 no longer hash in 5.8.9);
#   bcrypt: `$2<a|b|x|y>$<04..31>$` + 53 characters of [./A-Za-z0-9], 60 in all (emqx_authn_password_hashing.erl:220-224,
#     :252-253 the stored hash is the salt; erlang-bcrypt 0.6.2 in the 5.8.9 image writes $2a$ and verifies only these
#     minors and rounds: proven in that image, security review iteration 8);
#   plain: never acceptable (refused: PLAIN_REFUSED / PLAIN_ELSEWHERE).
# A row of a user group no built-in database authenticator of HA's configuration owns (its gateway or listener was
# removed) must have one of these forms (hex of 32, 40, 56, 64, 96 or 128 characters, or a bcrypt string). HA's broker
# answers the number of `plain` built-in password databases outside the global chain, the number of rows not in their
# form and the first ten of them as base64 user id + '.' + base64 user group; never a password, hash or salt. A row of an
# unknown shape answers `bad` (refused). Residual: a clear-text password that is itself exactly such a form.
PLAIN_EXPR = ('Lw = fun(X) when is_list(X) -> X; (X) when is_map(X) -> [X]; (_) -> [] end, '
              'Bn = fun(X) when is_atom(X) -> atom_to_binary(X, utf8); (X) when is_binary(X) -> X; (_) -> <<"?">> end, '
              'Ln = fun(M) when is_map(M) -> [{Tl, Nl, Cl} || {Tl, Lt} <- maps:to_list(M), is_map(Lt), '
              '{Nl, Cl} <- maps:to_list(Lt), is_map(Cl)]; (_) -> [] end, '
              'Cn = fun(F) -> case catch F() of Cx when is_atom(Cx) -> atom_to_binary(Cx, utf8); _ -> none end end, '
              'Db = fun(A) when is_map(A) -> maps:get(mechanism, A, none) =:= password_based andalso '
              'maps:get(backend, A, none) =:= built_in_database; (_) -> false end, '
              'Gw = [{G, Gc} || {G, Gc} <- maps:to_list(emqx:get_config([gateway], #{})), is_map(Gc)], '
              'All = [{<<"mqtt:global">>, global, A1} || A1 <- Lw(emqx:get_config([authentication], []))] '
              '++ [{<<(Bn(T2))/binary, ":", (Bn(N2))/binary>>, other, A2} || {T2, N2, C2} <- '
              'Ln(emqx:get_config([listeners], #{})), A2 <- Lw(maps:get(authentication, C2, []))] '
              '++ [{Cn(fun() -> emqx_gateway_utils:global_chain(G3) end), other, A3} || {G3, Gc3} <- Gw, '
              'A3 <- Lw(maps:get(authentication, Gc3, []))] '
              '++ [{Cn(fun() -> emqx_gateway_utils:listener_chain(G4, T4, N4) end), other, A4} || {G4, Gc4} <- Gw, '
              '{T4, N4, C4} <- Ln(maps:get(listeners, Gc4, #{})), A4 <- Lw(maps:get(authentication, C4, []))], '
              'Dbs = [{K, W, maps:get(password_hash_algorithm, A, #{})} || {K, W, A} <- All, Db(A)], '
              'Elsewhere = length([x || {_, other, H} <- Dbs, maps:get(name, H, none) =:= plain]), '
              'Hx = fun(V, Len) -> byte_size(V) =:= Len andalso lists:all(fun(Ch) -> (Ch >= $0 andalso Ch =< $9) '
              'orelse (Ch >= $a andalso Ch =< $f) orelse (Ch >= $A andalso Ch =< $F) end, binary_to_list(V)) end, '
              'Bc = fun(<<"$2", Mi, "$", R1, R2, "$", Tb/binary>>) when byte_size(Tb) =:= 53 -> '
              'lists:member(Mi, "abxy") andalso R1 >= $0 andalso R1 =< $9 andalso R2 >= $0 andalso R2 =< $9 andalso '
              '((R1 - $0) * 10 + R2 - $0) >= 4 andalso ((R1 - $0) * 10 + R2 - $0) =< 31 andalso '
              'lists:all(fun(Ch) -> (Ch >= $0 andalso Ch =< $9) orelse (Ch >= $a andalso Ch =< $z) orelse '
              '(Ch >= $A andalso Ch =< $Z) orelse Ch =:= $. orelse Ch =:= $/ end, binary_to_list(Tb)); '
              '(_) -> false end, '
              'Dk = #{sha => 20, sha224 => 28, sha256 => 32, sha384 => 48, sha512 => 64}, '
              'Fits = fun(Al, V) -> case maps:get(name, Al, none) of md5 -> Hx(V, 32); sha -> Hx(V, 40); '
              'sha256 -> Hx(V, 64); sha512 -> Hx(V, 128); bcrypt -> Bc(V); '
              'pbkdf2 -> case maps:get(dk_length, Al, undefined) of D when is_integer(D), D > 0 -> Hx(V, 2 * D); '
              '_ -> case maps:find(maps:get(mac_fun, Al, none), Dk) of {ok, D} -> Hx(V, 2 * D); error -> false end '
              'end; _ -> false end end, '
              'Any = fun(V) -> Bc(V) orelse lists:any(fun(Len) -> Hx(V, Len) end, [32, 40, 56, 64, 96, 128]) end, '
              'Fold = fun({user_info, {G, U}, V, S, _}, {N0, U0, B0}) when is_atom(G), is_binary(U), is_binary(V), '
              'is_binary(S) -> Kg = atom_to_binary(G, utf8), '
              'Ok = case [Al || {Ka, _, Al} <- Dbs, Ka =:= Kg] of [] -> Any(V); '
              'Als -> lists:all(fun(Al) -> Fits(Al, V) end, Als) end, '
              'case Ok of true -> {N0, U0, B0}; false -> {N0 + 1, [{Kg, U} | U0], B0} end; '
              '(_, {N0, U0, B0}) -> {N0, U0, B0 + 1} end, '
              '{Nc, Uc, Bad} = ets:foldl(Fold, {0, [], 0}, emqx_authn_mnesia), '
              'case Bad of 0 -> io:format("WOOWPLAIN:~b:~b:~s:END", [Elsewhere, Nc, lists:join(",", '
              '[[base64:encode(Ux), ".", base64:encode(Kx)] || {Kx, Ux} <- lists:sublist(lists:sort(Uc), 10)])]); '
              '_ -> io:format("WOOWPLAIN:bad:END") end.')


# ====================================================================== the add-on member

class Source:
    def __init__(self):
        self.addon = None
        self.node_file = None
        self.node_dirs = set()
        self.node_written = {}   # node dir -> the latest modification time of anything in it (E-07: the last written one)
        self.files = 0
        self.bytes = 0
        self.hocon = ''
        self.plugins = set()


def scan_member(stream, report, out=None, *, checkpoint=None):
    """One strict pass: HA's data dir items (STAGED) into `out` (a FileTar for the throwaway volume: names relative to
    the data dir, root-owned like on HA, dirs 0755, files 0644, nothing executable), cluster.hocon kept as text, the
    node name file read; the cookie, generated configs, plugins, patches, backups, traces and logs never."""
    select = habackup.Select(include=tuple(f'{DATA}/{item}' for item in STAGED) + (NODE_FILE, PLUGINS), symlinks=(),
                             hardlinks=False)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        name = entry.name
        if name == NODE_FILE:
            if entry.kind == 'file':
                src.node_file = entry.read_all(1024).decode('ascii', 'replace').strip()[:300]
            continue
        if ha_odoo._under(name, PLUGINS):
            rest = name[len(PLUGINS) + 1:]
            if rest and '/' not in rest:
                src.plugins.add(rest[:100])
            continue
        rel = name[len(DATA) + 1:]
        parts = rel.split('/')
        if parts[0] == 'mnesia' and (len(parts) >= 3 or len(parts) == 2 and entry.kind == 'dir'):
            src.node_dirs.add(parts[1][:300])
            if isinstance(entry.mtime, (int, float)) and not isinstance(entry.mtime, bool):
                src.node_written[parts[1][:300]] = max(src.node_written.get(parts[1][:300], 0), entry.mtime)
        if out is not None and len(parts) > 1:
            for depth in range(1, len(parts)):  # the folders above a selected file (configs/ has no entry of its own)
                parent = '/'.join(parts[:depth])
                if parent not in out.names:
                    out.add_member(hacommon.info(parent, 'dir', mode=0o755, uid=0, gid=0, mtime=entry.mtime))
        if entry.kind == 'dir':
            if out is not None and rel not in out.names:
                out.add_member(hacommon.info(rel, 'dir', mode=0o755, uid=0, gid=0, mtime=entry.mtime))
            continue
        src.files += 1
        src.bytes += entry.size
        if rel == 'configs/cluster.hocon':
            data = entry.read_all(MAX_HOCON)
            src.hocon = data.decode('utf-8', 'replace')
            if out is not None:
                out.add_member(hacommon.info(rel, 'file', mode=0o644, uid=0, gid=0, mtime=entry.mtime, size=len(data)),
                               io.BytesIO(data))
            continue
        if out is not None:
            out.add_entry(rel, entry, mode=0o600 if parts[0] == 'certs' else 0o644, uid=0, gid=0)
    src.addon = report.addon
    return src


def node_name(src):
    """(HA's node name, None) or (None, zh-TW blocker)."""
    dirs = sorted(d for d in src.node_dirs if '@' in d)
    name = src.node_file or (dirs[0] if len(dirs) == 1 else None)
    if not dirs:
        return None, 'HA 備份裡沒有 EMQX 的內建資料庫（mnesia），可能從來沒有啟動過；沒有可搬的資料。'
    if name is None:
        return None, (f'HA 的 EMQX 有 {len(dirs)} 個內建資料庫（{hacommon.names(dirs, 3)}）且沒有記錄使用哪一個；'
                      '請先在 HA 設定 EMQX_NODE__NAME 選定後重新備份。')
    if not NODE_RE.fullmatch(name):
        return None, 'HA 的 EMQX 節點名稱格式不受支援。'
    if name not in dirs:
        return None, f'HA 的 EMQX 節點 {name} 沒有對應的內建資料庫。'
    return name, None


NO_DATABASE = 'HA 備份裡沒有 EMQX 的內建資料庫（mnesia），可能從來沒有啟動過；沒有可搬的資料。'
NO_DATABASE_ACTION = '請先在 HA 啟動一次 EMQX 附加元件（讓它建立資料），再重新備份後匯入；這台的 EMQX 不會變，其他應用照常匯入。'


def pick_node(src, chosen=None):
    """Which of HA's node databases is moved (E-06, E-07, E-09): (name, rows, said). `chosen`: what the customer picked
    (`choices.node`). The recorded node name when the backup has that database; else the only one there is; else the one
    written last (HA changed its host name and left the old database behind). `rows`: `choices.node` ([{value, label,
    default}]) when there is something to choose from, else []; `said`: the sentence of the `auto` line when this device
    picked, else None. Stops only this app (`emqx.no-database`, `emqx.node-gone`)."""
    dirs = sorted(d for d in src.node_dirs if '@' in d)
    if not dirs:
        raise haissues.stopped(haissues.Issue('emqx.no-database', 'stop', NO_DATABASE, action=NO_DATABASE_ACTION))
    if chosen is not None:
        if chosen not in dirs or not NODE_RE.fullmatch(chosen):
            raise haissues.stopped(haissues.Issue(
                'emqx.node-gone', 'stop', 'HA 的 EMQX 資料庫「' + haissues.clean(chosen, 120) + '」不在這份備份裡。', dirs[:10],
                action='請重新檢查這份備份，再選一個備份裡有的 EMQX 資料庫。'))
        return chosen, [], None
    recorded = src.node_file
    if recorded in dirs and NODE_RE.fullmatch(recorded):
        return recorded, [], None
    if len(dirs) == 1:
        name = dirs[0]
        said = (f'HA 記錄的 EMQX 節點 {haissues.clean(recorded, 120)} 沒有對應的資料庫，改用備份裡唯一的資料庫 {haissues.clean(name, 120)}。'
                if recorded else None)
        picked = name
        rows = []
    else:
        picked = max(dirs, key=lambda d: (src.node_written.get(d, 0), d))
        said = (f'HA 的 EMQX 有 {len(dirs)} 個內建資料庫，備份沒有記錄用的是哪一個；已自動選最後寫入的 {haissues.clean(picked, 120)}，'
                '可以在頁面改選。')
        rows = []
        for name in dirs:
            written = src.node_written.get(name)
            when = (f'最後寫入 {time.strftime("%Y-%m-%d", time.gmtime(written))}' if isinstance(written, (int, float))
                    and 0 < written < 2 ** 40 else '最後寫入時間不明')
            rows.append({'value': name, 'label': f'{name}（{when}）', 'default': name == picked})
    if not NODE_RE.fullmatch(picked):
        raise haissues.stopped(haissues.Issue('emqx.node-gone', 'stop', 'HA 的 EMQX 節點名稱格式不受支援。',
                                              action='請在 HA 重新備份後再匯入。'))
    return picked, rows, said


def hocon_notes(text):
    """Warnings about HA's cluster.hocon: HA-only hosts of connectors/bridges and files outside the data dir."""
    notes = []
    hosts = hacommon.ha_hosts(text)
    if hosts:
        notes.append(f'HA 的 EMQX 規則、連接器或橋接連到 HA 內部的位址（{hacommon.names(hosts, 8)}），這台連不到，'
                     '搬過來後請改成實際位址。')
    paths = sorted({m.group(0)[:80] for m in re.finditer(r'"(?:/ssl|/share|/config)/[^"\s]{1,200}"', text[:MAX_HOCON])})
    if paths:
        notes.append(f'HA 的 EMQX 設定引用了資料夾以外的檔案（{hacommon.names(paths, 3)}），這些檔案不會搬過來。')
    return notes


# ====================================================================== the live target

MQTT_PORTS = frozenset({'1883', '8883', '8083', '8084'})
DASHBOARD_PORTS = frozenset({'18083', '18084'})
LOCAL_ADDRESSES = frozenset({'127.0.0.1', '::1', 'localhost'})


def parse_publish(value):
    """(host address, host port, container port) of one Quadlet `PublishPort=` value (the address '' = every interface), or
    None when it is not one of the forms podman reads: `[ip:][host port:]container port[/protocol]`. Names only."""
    spec = str(value).strip().strip('"\'').split('/', 1)[0]
    if spec.startswith('['):
        address, _sep, rest = spec[1:].partition(']')
        parts = rest.lstrip(':').split(':')
    else:
        parts = spec.split(':')
        address = parts.pop(0) if len(parts) >= 3 else ''
    if len(parts) == 2:
        host, container = parts
    elif len(parts) == 1:
        host = container = parts[0]
    else:
        return None
    if not (re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', host or '') and re.fullmatch(r'[0-9]{1,5}', container or '')):
        return None
    return address, host, container


def reachable_from_network(rows, ports=None):
    """Whether one of the published `rows` ((address, host port, container port)) lets more than this device in: an address
    that is not the loopback (every interface, a LAN address). `ports`: only rows whose container port is among these."""
    return any(address.lower() not in LOCAL_ADDRESSES and not address.startswith('127.')
               for address, _host, container in rows if ports is None or container in ports)


def exposure(target, ports):
    """'network' | 'local' | 'closed': MQTT or Dashboard (`ports`) on this device as its installed Quadlet files publish them
    (already rendered to real addresses). 'closed': no published port at all (only other containers on the app's network
    can connect). A tunnel container (`target.tunnels`) is named by the caller: it cannot be told from here what it opens."""
    rows = [row for row in target.publish if row[2] in ports]
    if ports is DASHBOARD_PORTS:
        rows += target.other_publish   # an entrance or proxy of the app may front the Dashboard
    if not rows:
        return 'closed'
    return 'network' if reachable_from_network(rows) else 'local'


class Target:
    """The emqx app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        declared = [v['name'] for v in app.volumes]
        broker, data_volume = hacommon.mounted(quadlets, home, DATA_TARGET)
        _b, log_volume = hacommon.mounted(quadlets, home, LOG_TARGET, files=[broker] if broker else None)
        if (broker is None or sorted(declared) != sorted({data_volume, log_volume} - {None}) or len(declared) != 2
                or app.postgres or app.data_dirs):
            raise BackupError('incompatible', '這台的 EMQX 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        text = quadlets[broker]
        self.container = hacommon.quadlet_container_name(quadlets, broker)
        self.data_volume, self.log_volume = data_volume, log_volume
        self.image = tempctr.quadlet_image(text)
        if not self.image:
            raise BackupError('incompatible', '這台 EMQX 的 Quadlet 設定缺少映像。', app=app.id)
        keys = set(re.findall(r'(?m)^\s*Environment\s*=\s*"?(EMQX_[A-Z0-9_]{1,100})=',
                              text.decode('utf-8', 'replace') if isinstance(text, bytes) else str(text)))
        self.env = tempctr.quadlet_environment(text, keys)
        self.secrets = tempctr.quadlet_secrets(text)
        self.files = [(s, t, 'ro') for s, t, _o in ha_odoo.quadlet_mounts(quadlets, broker, home)
                      if s.startswith('/') and t not in (DATA_TARGET, LOG_TARGET)]
        self.node = self.env.get('EMQX_NODE__NAME', 'emqx@127.0.0.1')
        body = text.decode('utf-8', 'replace') if isinstance(text, bytes) else str(text)
        self.env_files = [value for key, value in tempctr.parse_unit(body).get('Container', [])
                          if key == 'EnvironmentFile']
        self._runner = work.runner(app)
        self.publish = [row for row in (parse_publish(value) for key, value in
                                        tempctr.parse_unit(body).get('Container', []) if key == 'PublishPort') if row]
        # What else of the app's own Quadlet files is reachable from outside: other containers' published ports (an
        # entrance that fronts the Dashboard) and tunnels to the outside (ngrok, a Cloudflare tunnel).
        self.other_publish, self.tunnels = [], []
        for name, other in sorted(quadlets.items()):
            if name == broker:
                continue
            other_body = other.decode('utf-8', 'replace') if isinstance(other, bytes) else str(other)
            section = tempctr.parse_unit(other_body).get('Container', [])
            # a tunnel to the outside is told by what the file is (its name, its container, its image), never by a word in a comment
            names = [name] + [value for key, value in section if key in ('ContainerName', 'Image')]
            if any(re.search(r'(?i)ngrok|cloudflared|tunnel', text) for text in names):
                self.tunnels.append(name.rsplit('.', 1)[0][:60])
            self.other_publish += [row for row in (parse_publish(value) for key, value in section
                                                   if key == 'PublishPort') if row]
        self.access_env = []   # names of EMQX_AUTHORIZATION__* / EMQX_AUTHENTICATION__* settings of this device (H1)
        self.skipped_env = []  # EnvironmentFile= paths the candidate does not get (E-53), for the log

    def candidate_env(self):
        """The environment this device's broker runs with, for the candidate, as (env, env_files): `env` holds the
        Quadlet's `Environment=` EMQX_* settings (podman --env, on the command line as this device's own Quadlet puts
        them), `env_files` the absolute paths of its `EnvironmentFile=` files (dev-d's product package sets
        EMQX_LOG__CONSOLE__LEVEL there, 2026-11-23 attempt-06), which podman reads for the candidate with --env-file
        exactly as for this device's broker. Their values never reach a command line: such a file may hold secrets
        (CONTRACT keeps it 0600) and every local account can read /proc/<pid>/cmdline (security review SR-8,
        2026-11-24: a value passed with --env was in two world-readable command lines; tempctr.run_argv, podman.py's
        runner rule). podman's own parser reads them, so the candidate gets what the running broker got (SR-9).
        E-53: what a file holds is no longer judged here (quotes, escapes, `$`, doubles): the candidate starts with the
        same files, and what that changes shows in the comparison of its settings with this device's (E-60). A file that
        is not under the owner's home or cannot be read is left out of the candidate and said in the log. The names of
        this device's own EMQX_AUTHORIZATION__* / EMQX_AUTHENTICATION__* settings are kept (`access_env`: names only,
        never a value; H1: they win over HA's after the next start)."""
        env, files = dict(self.env), []
        home = str(self._runner.home).rstrip('/')
        names = {key for key in env if ACCESS_ENV.match(key)}
        for spec in self.secrets:
            names |= {m for m in re.findall(r'target=(EMQX_(?:AUTHORIZATION|AUTHENTICATION)__[A-Z0-9_]{0,90})', spec)}
        for value in self.env_files:
            optional = value.startswith('-')
            path = value.lstrip('-')
            rel = path[3:] if path.startswith('%h/') else None
            if rel is None or not re.fullmatch(r'[A-Za-z0-9._/-]{1,200}', rel) or '..' in rel.split('/'):
                self.skipped_env.append(path[:120])
                continue
            try:
                data = self._runner.read_file(rel, max_bytes=256 * 1024)
            except BackupError:
                if not optional:
                    self.skipped_env.append(path[:120])
                continue
            for raw in data.split(b'\n'):
                match = ACCESS_ENV_LINE.match(raw.decode('utf-8', 'replace').lstrip(' \t'))
                if match:
                    names.add(match.group(1))
            files.append(f'{home}/{rel}')
        self.access_env = sorted(names)
        return env, files


# ====================================================================== the brokers

def ctl(tmp, role, args, *, timeout=600, check=True):
    return tmp.exec(role, ['emqx', 'ctl', *args], timeout=timeout, max_output=4 * 1024 * 1024, check=check)


def evaluate(tmp, role, expression):
    """`emqx eval` of a fixed expression; its printed value."""
    out = tmp.exec(role, ['emqx', 'eval', expression], timeout=300, max_output=4 * 1024 * 1024).stdout or b''
    return out.decode('utf-8', 'replace')


def quiesce_system_ticker(tmp, role):
    """Freeze status publication only in isolated job brokers during row validation.

    EMQX's ticker adds three retained $SYS records asynchronously. Suspending this
    process keeps all rows counted and imported without rewriting settings or
    ignoring any topic. Stopping/restarting the temporary broker ends the pause.

    E-13: the pid of the paused process, or None when it could not be paused (the broker did not answer as expected):
    that is no reason to stop (the retained messages may then differ by a few rows, which the count check allows for:
    SYS_SLACK) and the caller says so in a notice."""
    if role not in ('emqx-ha', 'emqx-new'):
        raise BackupError('internal-error', '只能暫停隔離匯入容器的系統訊息。')
    try:
        value = evaluate(tmp, role, SUSPEND_SYS_EXPR)
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return None
    match = re.fullmatch(r'WOOWSYS:(<[0-9]+\.[0-9]+\.[0-9]+>):suspended\s*(?:ok\s*)?', value)
    return match.group(1) if match else None


def assert_system_ticker(tmp, role, pid):
    """Whether the paused process is still the paused one (True); False when it changed or restarted midway (E-13: the
    caller allows for it in the row count and says so). `pid` None (nothing was paused): False."""
    if role not in ('emqx-ha', 'emqx-new') or not (pid is None or re.fullmatch(r'<[0-9]+\.[0-9]+\.[0-9]+>', pid)):
        raise BackupError('internal-error', '暫用 EMQX 的系統程序識別不正確。')
    if pid is None:
        return False
    try:
        return evaluate(tmp, role, TICKER_STATUS_EXPR.replace('{pid}', pid)).strip() == 'ticker_unchanged'
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return False


READY_EXTENDED = 3600   # a broker that still runs when the wait is over is given this much more (E-12)


def wait_ready(tmp, role, *, checkpoint, hint='', sleep=time.sleep, clock=time.monotonic, timeout=READY_TIMEOUT,
               size=None, extend=READY_EXTENDED):
    """Wait until the throwaway broker answers `emqx ctl status`. E-12: the wait grows with the data (`size`: bytes, about
    how much the broker has to load: podman.scaled_timeout) and, when it is over and the broker still runs (it is only
    slow), goes on for `extend` seconds more; the job's cancel is asked at every step (`checkpoint`). The broker that really
    ended stops the app at once, the one that never gets ready after all that does too."""
    limit = podman.scaled_timeout(timeout, size)
    deadline = clock() + limit
    extended = False
    while True:
        if checkpoint is not None:
            checkpoint()
        result = ctl(tmp, role, ['status'], timeout=60, check=False)
        if result.returncode == 0 and b'is started' in (result.stdout or b''):
            return
        if not tmp.running(role):
            raise BackupError('incompatible', '暫用的 EMQX 無法開啟這份資料（設定或資料可能不完整或不相容）。' + hint)
        if clock() > deadline:
            if extended or not extend:
                raise BackupError('incompatible', f'暫用的 EMQX 在 {limit + (extend if extended else 0)} 秒內沒有就緒。' + hint)
            extended = True   # still running: only slow
            deadline = clock() + extend
        sleep(2)


def hint_for(addon):
    """The advice for a failure on HA's data: a backup made while EMQX ran may hold a half-written database."""
    return HOT_HINT if addon is None or addon.state != 'stopped' else ''


def parse_counts(text):
    counts = {name: int(value) for name, value in re.findall(r'\{\s*([a-z_]+)\s*,\s*(-?[0-9]{1,12})\s*\}', text)
              if name in TABLES}
    if any(value < -1 for value in counts.values()):
        raise BackupError('job-failed', 'EMQX 資料筆數無法穩定讀取，已停止。')
    return counts


def parse_authn(text):
    rows = re.findall(r'\{\s*([a-z_]+)\s*,\s*([a-z_]+)\s*,\s*(true|false)\s*,\s*([a-z0-9_]+)\s*,'
                      r'\s*([a-z_]+)\s*\}', text)
    return [{'mechanism': m, 'backend': b, 'enable': e == 'true', 'algorithm': a, 'salt': s} for m, b, e, a, s in rows]


AUTHN_ROW = (r'\{\s*[a-z_]{1,40}\s*,\s*[a-z_]{1,40}\s*,\s*(?:true|false)\s*,\s*[a-z0-9_]{1,40}\s*,\s*[a-z_]{1,40}\s*\}')
AUTHN_ANSWER = re.compile(r'\s*\[\s*(?:' + AUTHN_ROW + r'(?:\s*,\s*' + AUTHN_ROW + r')*)?\s*\]\s*(?:ok\s*)?')


def parse_authz(text):
    """AUTHZ_EXPR's answer as [{'type', 'enable'}] in order; None when it is not that shape."""
    body = (text or '').strip()
    if not re.fullmatch(r'\[\s*(?:\{\s*[a-z_]{1,40}\s*,\s*(?:true|false)\s*\}(?:\s*,\s*\{\s*[a-z_]{1,40}\s*,\s*(?:true|false)\s*\})*)?\s*\]',
                        body.split('\nok')[0].strip() if body.endswith('ok') else body):
        return None
    return [{'type': kind, 'enable': enable == 'true'}
            for kind, enable in re.findall(r'\{\s*([a-z_]{1,40})\s*,\s*(true|false)\s*\}', body)]


def parse_strict(text):
    match = re.search(r'\{\s*(allow|deny)\s*,\s*(ignore|disconnect)\s*\}', text)
    return (match.group(1), match.group(2)) if match else None


HASH_ROW = (r'\{\s*(true|false)\s*,\s*([a-z][a-z0-9_]{0,31})\s*,\s*([a-z][a-z_]{0,31})\s*,\s*([a-z][a-z0-9_]{0,31})\s*,'
            r'\s*([0-9]{1,10}|none|undefined)\s*,\s*([0-9]{1,10}|none|undefined)\s*\}')
HASH_ANSWER = re.compile(r'\s*\[\s*(?:' + HASH_ROW + r'(?:\s*,\s*' + HASH_ROW + r')*)?\s*\]\s*')
USERS_ANSWER = re.compile(r'\s*WOOWUSERS:([0-9]{1,9}):((?:[A-Za-z0-9+/]{1,87384}={0,2})'
                          r'(?:,[A-Za-z0-9+/]{1,87384}={0,2}){0,9})?:END(?:ok)?\s*')
# One PLAIN_EXPR item: base64 user id '.' base64 user group (a chain name: an atom, at most 255 characters).
PLAIN_ITEM = r'[A-Za-z0-9+/]{1,87384}={0,2}\.[A-Za-z0-9+/]{1,1400}={0,2}'
PLAIN_ANSWER = re.compile(r'\s*WOOWPLAIN:([0-9]{1,9}):([0-9]{1,9}):((?:' + PLAIN_ITEM + r')(?:,' + PLAIN_ITEM +
                          r'){0,9})?:END(?:ok)?\s*')


def parse_hashing(text):
    """HASH_EXPR's answer: None (no built-in password database authenticator) or its hashing {enable, name, salt,
    mac_fun, iterations, dk_length} (a field the algorithm does not have: None). Any other answer -- two rows, a cut or
    unknown shape -- raises ValueError: the callers refuse rather than guess (SR-5)."""
    if not HASH_ANSWER.fullmatch(text or ''):
        raise ValueError('unreadable hashing')
    rows = re.findall(HASH_ROW, text)
    if len(rows) > 1:
        raise ValueError('more than one built-in password database authenticator')
    if not rows:
        return None
    enable, name, salt, mac_fun, iterations, dk_length = rows[0]

    def field(value):
        return None if value in ('none', 'undefined') else value
    return {'enable': enable == 'true', 'name': name, 'salt': field(salt), 'mac_fun': field(mac_fun),
            'iterations': None if field(iterations) is None else int(iterations),
            'dk_length': None if field(dk_length) is None else int(dk_length)}


def parse_users(text):
    """USERS_EXPR's answer: (the number of users, the first ten user ids as text). Anything else raises ValueError."""
    match = USERS_ANSWER.fullmatch(text or '')
    if not match:
        raise ValueError('unreadable users')
    count = int(match.group(1))
    try:
        names = [base64.b64decode(item, validate=True).decode('utf-8', 'replace')
                 for item in (match.group(2).split(',') if match.group(2) else [])]
    except (ValueError, TypeError):
        raise ValueError('unreadable users') from None
    if len(names) != min(count, 10):
        raise ValueError('unreadable users')
    return count, names


def parse_plain(text):
    """PLAIN_EXPR's answer: {'elsewhere': `plain` built-in password databases outside the global chain, 'clear': rows
    not stored in the form of their authenticator's hashing (possibly clear text), 'names': the first ten of them as
    (user id, user group) text}. Anything else -- a row of an unknown shape (`bad`), a cut, a count that does not match
    the names -- raises ValueError: the callers refuse (SR-5)."""
    match = PLAIN_ANSWER.fullmatch(text or '')
    if not match:
        raise ValueError('unreadable plain answer')
    clear = int(match.group(2))
    try:
        names = [tuple(base64.b64decode(part, validate=True).decode('utf-8', 'replace') for part in item.split('.'))
                 for item in (match.group(3).split(',') if match.group(3) else [])]
    except (ValueError, TypeError):
        raise ValueError('unreadable plain answer') from None
    if len(names) != min(clear, 10):
        raise ValueError('unreadable plain answer')
    return {'elsewhere': int(match.group(1)), 'clear': clear, 'names': names}


def ha_broker(work, tmp, target, src, node, *, out_dir=None):
    """Start HA's broker on its staged data; returns its readings (and, with `out_dir`, the export file's path in
    `out_dir`). The caller removes the objects. Anything that shows HA's database did not load completely -- the broker
    does not start, a table every 5.8.9 broker has is missing, EMQX's own export fails -- refuses the import with the
    advice to back up again with the add-on stopped: a result is never silently incomplete.

    Readings: `default_admin`, `counts`, `roots`, `authn` (HA's authenticators), `authz` (its authorization sources in
    order: [{type, enable}]), `strict` (no_match, deny_action), `hashing` and `plain` (D1: how MQTT passwords are stored;
    None with `hash_unreadable` when they could not be read: E-16, never a stop) and `ticker` (False when the system
    messages could not be paused: E-13)."""
    hint = hint_for(src.addon)
    host = node.split('@', 1)[1]
    hosts = [] if IPV4_RE.fullmatch(host) else [(host, '127.0.0.1')]
    # No cookie is set: the image's default only guards the distribution port inside a container without a network.
    # An empty default password: no Dashboard user is created at boot (emqx_dashboard_admin:add_default_user), so the
    # export holds HA's users only.
    # HA's cluster.hocon may name plugins and the folder they load from: EMQX 5.8.9 loads and starts every enabled
    # plugin at boot (emqx_plugins_app.erl:31-33, emqx_plugins.erl:310-321,1023-1066; `noexec` does not stop BEAM
    # loading), so a crafted backup staging one under certs/ ran its code here (security review SR-1, B1-06 port of
    # e848015). Environment overrides win over cluster.hocon: no plugin, the image's own empty plugin folder.
    env = {'EMQX_NODE__NAME': node, 'EMQX_NODE__DATA_DIR': HA_DATA_DIR, 'EMQX_DASHBOARD__DEFAULT_PASSWORD': '',
           'EMQX_PLUGINS__STATES': '[]', 'EMQX_PLUGINS__INSTALL_DIR': '/opt/emqx/plugins'}
    volumes = [(tmp.name('emqx-src'), HA_DATA_DIR, 'rw,noexec,nosuid,nodev')]
    if out_dir is not None:
        tmp.volume('emqx-xfer')
        tmp.volume_import('emqx-xfer', lambda out: _folder_tar(out, 'out', 0, 0))
        volumes.append((tmp.name('emqx-xfer'), WORK, 'rw,noexec,nosuid,nodev'))
    tmp.volume('emqx-ha-log')
    volumes.append((tmp.name('emqx-ha-log'), LOG_TARGET, 'rw,noexec,nosuid,nodev'))
    # The image declares VOLUME /opt/emqx/data and /opt/emqx/log: a path no mount covers gets an anonymous volume that
    # `podman rm` keeps (dev-d 2026-11-24: one left on the device by every check and every conversion). This broker's
    # data lives in HA_DATA_DIR; the image path gets this job's own volume, removed with the others.
    tmp.volume('emqx-ha-image')
    volumes.append((tmp.name('emqx-ha-image'), DATA_TARGET, 'rw,noexec,nosuid,nodev'))
    try:
        tmp.run('emqx-ha', target.image, [], detach=True, user='0', read_only_root=True, add_hosts=hosts, env=env,
                volumes=volumes)
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise BackupError('incompatible', f'無法以 HA 的 EMQX 節點名稱 {node} 啟動暫用的 EMQX。') from None
    wait_ready(tmp, 'emqx-ha', checkpoint=work.checkpoint, hint=hint, size=src.bytes)
    ticker_pid = quiesce_system_ticker(tmp, 'emqx-ha')
    readings = {'default_admin': 'default' in evaluate(tmp, 'emqx-ha', DEFAULT_ADMIN_EXPR).split(),
                'counts': parse_counts(evaluate(tmp, 'emqx-ha', COUNT_EXPR)),
                'roots': set(re.findall(r'<<"([a-z_]+)">>', evaluate(tmp, 'emqx-ha', ROOTS_EXPR))),
                'authn': evaluate(tmp, 'emqx-ha', AUTHN_EXPR),
                'authz': parse_authz(evaluate(tmp, 'emqx-ha', AUTHZ_EXPR)),
                'strict': parse_strict(evaluate(tmp, 'emqx-ha', STRICT_EXPR))}
    # S2: an empty list IS an answer (HA's broker asks nobody to log in) and makes this device's authenticators go; an
    # answer that is not exactly the list is not that answer and is never guessed (the same as authorization below).
    if not AUTHN_ANSWER.fullmatch(readings['authn']):
        raise BackupError('incompatible', '無法讀取 HA 的 EMQX 帳號驗證設定。' + hint)
    readings['authn'] = parse_authn(readings['authn'])
    if len(readings['counts']) != len(TABLES):
        raise BackupError('incompatible', '無法讀取 HA 的 EMQX 資料筆數。' + hint)
    if readings['authz'] is None or readings['strict'] is None:   # D0 makes them this device's: never guessed
        raise BackupError('incompatible', '無法讀取 HA 的 EMQX 授權設定。' + hint)
    missing = [t for t in REQUIRED_TABLES if readings['counts'].get(t, -1) < 0]
    if missing:
        raise BackupError('incompatible', f'HA 的 EMQX 內建資料庫沒有完整載入（缺少 {hacommon.names(missing)}）。' + hint)
    try:   # D1 (SR-5 before): how MQTT passwords are stored, named in a notice; never a reason to stop (E-16)
        readings['hashing'] = parse_hashing(evaluate(tmp, 'emqx-ha', HASH_EXPR))
        readings['plain'] = parse_plain(evaluate(tmp, 'emqx-ha', PLAIN_EXPR))   # listeners, gateways, old rows
        readings['hash_unreadable'] = False
    except ValueError:
        readings['hashing'], readings['plain'], readings['hash_unreadable'] = None, None, True
    readings['ticker'] = assert_system_ticker(tmp, 'emqx-ha', ticker_pid)
    if out_dir is not None:
        roots = [root for root in DATA_ROOTS if root in readings['roots']]
        out = ctl(tmp, 'emqx-ha', ['data', 'export', '--root-keys', ','.join(roots), '--table-sets',
                                   ','.join(TABLE_SETS), '--dir', f'{WORK}/out'], timeout=1800).stdout or b''
        match = EXPORT_RE.search(out)
        if not match:
            raise BackupError('incompatible', 'EMQX 無法匯出 HA 的資料。' + hint)
        readings['export'] = match.group(1).decode('ascii')
        readings['ticker'] = readings['ticker'] and assert_system_ticker(tmp, 'emqx-ha', ticker_pid)
    return readings


def _folder_tar(out, folder, uid, gid, files=()):
    """A tar of one folder (and `files` [(name, path)]) for `podman volume import`."""
    tar = tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT)
    tar.addfile(hacommon.info('.', 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
    tar.addfile(hacommon.info(folder, 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
    for name, path in files:
        with open(path, 'rb') as handle:
            tar.addfile(hacommon.info(f'{folder}/{name}', 'file', mode=0o644, uid=uid, gid=gid, mtime=time.time(),
                                      size=os.fstat(handle.fileno()).st_size), handle)
    tar.close()


def take_export(work, tmp, path, staging):
    """The export file out of the transfer volume (a strict, bounded read of `podman volume export`)."""
    xfer = staging / 'xfer.tar'
    with open(xfer, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.volume_export('emqx-xfer', handle, max_output=work.guard.budget())
    wanted = path[len(WORK) + 1:]
    dest = staging / os.path.basename(path)
    found = False
    try:
        with ha_odoo._live_tar(xfer, 'EMQX 的匯出資料') as tar:
            for member in tar:
                if ha_odoo._norm(member.name) == wanted and member.isfile():
                    if member.size > MAX_EXPORT:   # larger than any database this engine could have exported (sanity)
                        raise BackupError('incompatible', 'HA 的 EMQX 匯出資料的大小不合理，已停止；這台沒有任何改變。')
                    work.guard.check(member.size)   # E-64: room for the copy decides, not a fixed size
                    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with os.fdopen(fd, 'wb') as out:
                        source = tar.extractfile(member)
                        while True:
                            data = source.read(habackup.CHUNK)
                            if not data:
                                break
                            out.write(data)
                    found = True
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', 'EMQX 的匯出資料無法讀取。') from None
    os.unlink(xfer)
    if not found:
        raise BackupError('job-failed', '找不到 HA 的 EMQX 匯出資料。')
    return dest


EXPORT_NAME_RE = re.compile(r'[A-Za-z0-9.-]{1,80}\.tar\.gz\Z')
EXPORT_TAMPERED = ('EMQX 不能搬過來：HA 匯出的資料含有不屬於這次匯入的內容（{what}），已在匯入前停止，這台沒有任何改變；'
                   '請在 HA 停止 EMQX 附加元件後重新備份再匯入。')
EXPORT_UNREADABLE = 'EMQX 不能搬過來：HA 匯出的資料在匯入前無法檢查，已停止，這台沒有任何改變。'
MAX_LISTING = 1024 * 1024
# What the vendor import would read from HA's export (emqx_mgmt_data_backup.erl:880-900 erl_tar, :904-912 hocon), listed
# in the candidate by those very functions on the very file before anything is imported: a second parser here would
# read a crafted archive or HOCON document differently. `include` makes hocon read another file (hocon 0.44.0,
# hocon_token:load_include) and EMQX's own export never writes one. Fixed but for the checked file name (argv).
EXPORT_EXPR = ('F = "{path}", {ok, L} = erl_tar:table(F, [compressed, verbose]), '
               'C = filename:basename(F, ".tar.gz") ++ "/cluster.hocon", '
               'R = case [{T, S} || {N, T, S, _, _, _, _} <- L, N =:= C] of '
               '[{regular, Z}] when Z =< {limit} -> '
               '{ok, [{C, B}]} = erl_tar:extract(F, [compressed, memory, {files, [C]}]), '
               '{ok, K, _} = hocon_scanner:string(unicode:characters_to_list(B)), '
               'false = lists:keymember(include, 1, K), {ok, H} = hocon:binary(B), maps:keys(H); _ -> [] end, '
               'io:format("WOOWEXP:~s:END~n", [base64:encode(emqx_utils_json:encode(#{roots => R, members => '
               '[[unicode:characters_to_binary(N), T, S] || {N, T, S, _, _, _, _} <- L]}))]).')


def export_expression(name):
    if not EXPORT_NAME_RE.match(name):
        raise BackupError('internal-error', 'EMQX 匯出檔名不正確。')
    return EXPORT_EXPR.replace('{path}', f'{WORK}/in/{name}').replace('{limit}', str(MAX_HOCON))


def check_export(execute, name, *, hint=''):
    """Refuse an export that holds anything ha_broker did not ask for, before `emqx ctl data import` applies it.

    ha_broker exports DATA_ROOTS and TABLE_SETS only, but the file was written by HA's broker from HA's own data. The
    vendor import unpacks every archive member into the candidate's data volume (emqx_mgmt_data_backup.erl:880-884) and
    applies every root it has an importer for at once (:68-90, :983-1050, the emqx_config_backup modules). Allowed:
    META.hocon, cluster.hocon with DATA_ROOTS only and the backup files of TABLES, each once and a regular file, in the
    export's own folder. This is defence in depth: whatever the import changed, every setting of this device is compared
    whole afterwards (restore_target_settings). Member and root names only, never values."""
    base = name[:-len('.tar.gz')]
    try:
        result = execute(['emqx', 'eval', export_expression(name)])
        body = result.stdout or b''
        if result.returncode or not body.startswith(b'WOOWEXP:'):
            raise ValueError()
        encoded, tail = body[8:].split(b':END', 1)
        if tail.strip() not in (b'', b'ok'):
            raise ValueError()
        listing = util.loads_strict(base64.b64decode(encoded, validate=True), max_bytes=MAX_LISTING)
        members, roots = listing['members'], listing['roots']
        if (len(listing) != 2 or type(members) is not list or type(roots) is not list
                or any(type(root) is not str for root in roots)
                or any(type(row) is not list or [type(value) for value in row] != [str, str, int] for row in members)):
            raise ValueError()
    except (ValueError, TypeError, KeyError, RecursionError):
        raise BackupError('incompatible', EXPORT_UNREADABLE + hint) from None
    limits = {f'{base}/META.hocon': MAX_HOCON, f'{base}/cluster.hocon': MAX_HOCON}
    limits.update({f'{base}/mnesia/{table}': MAX_EXPORT for table in TABLES})
    seen = set()
    for member, kind, size in members:
        if kind != 'regular' or member in seen or not 0 <= size <= limits.get(member, -1):
            raise BackupError('incompatible', EXPORT_TAMPERED.format(what='檔案 ' + hacommon.names([member])))
        seen.add(member)
    extra = sorted(set(roots) - set(DATA_ROOTS))
    if extra:
        raise BackupError('incompatible', EXPORT_TAMPERED.format(what='設定 ' + hacommon.names(extra)))


def target_config_snapshot(volume_tar, snapshot_path, required, *, limit=MAX_HOCON, absent=(), missing=None):
    """Stage named target config/ACL files from a volume export. Callers must enumerate effective references.

    This deliberately does not discover HOCON references or merge HA settings. Duplicate, linked, unsafe or too large
    paths fail closed. E-55: a file the settings name that is not in the volume stops the app unless `missing` (a list)
    is given: the names are put there instead (the candidate then starts without them, as this device's own broker has).
    """
    names = set(required)
    absent=set(absent)
    if absent - {'configs/cluster.hocon'} or absent - names:
        raise BackupError('incompatible', '不允許略過目標 EMQX 的必要設定參照。')
    if not names or 'configs/cluster.hocon' not in names:
        raise BackupError('incompatible', '缺少目標 EMQX 設定快照所需的檔案清單。')
    for name in names:
        if not snapshot_name_ok(name):
            raise BackupError('incompatible', '目標 EMQX 設定參照了不允許的路徑。')
    found, total = set(), 0
    out = hacommon.FileTar(snapshot_path)
    try:
        with ha_odoo._live_tar(volume_tar, '目標 EMQX 設定') as source:
            for member in source:
                name = ha_odoo._norm(member.name)
                if name is None:
                    raise BackupError('incompatible', '目標 EMQX 資料卷含有不安全的路徑。')
                if name in absent:
                    raise BackupError('incompatible', 'EMQX 原本不存在的覆寫檔於快照期間出現，已停止。')
                if any(required.startswith(name + '/') for required in names) and not member.isdir():
                    raise BackupError('incompatible', 'EMQX 設定檔的上層不是一般目錄，已停止。')
                if name in names:
                    if name in found or not member.isfile() or member.size < 0:
                        raise BackupError('incompatible', '目標 EMQX 設定檔重複或不是一般檔案。')
                    total += member.size
                    if total > limit:
                        raise BackupError('incompatible', '目標 EMQX 設定檔超過大小限制。')
                    info = ha_odoo._copy_info(member, name)
                    info.mode = 0o600
                    out.add_member(info, source.extractfile(member))
                    found.add(name)
                source.members.clear()
        if found != names - absent:
            if missing is None:
                raise BackupError('incompatible', '目標 EMQX 設定參照的檔案不存在，已停止。')
            missing.extend(sorted(names - absent - found))
    except Exception:
        out.close()
        os.unlink(snapshot_path)
        raise
    else:
        out.close()
    return found


def ascii_path(value):
    """`value` as text when it is a path (E-28): a string, or the list of ASCII character codes EMQX itself makes of a
    path it generated (an ACL file written from the Dashboard, a path not yet re-read after a restart); else None."""
    if isinstance(value, str):
        return value
    if (isinstance(value, list) and value and len(value) <= 4096
            and all(type(char) is int and 0 < char < 128 for char in value)):
        return ''.join(map(chr, value))
    return None


def _text_path(value):
    """`value` as text when it is a path a setting holds: a string, or the list of printable ASCII codes EMQX makes of a path
    it wrote itself (ascii_path); else None."""
    if isinstance(value, str):
        return value
    if (isinstance(value, list) and value and len(value) <= 4096
            and all(type(char) is int and 32 <= char < 127 for char in value)):
        return ''.join(map(chr, value))
    return None


PATH_ENV = re.compile(r'\$(?:\{([A-Za-z_][A-Za-z0-9_]{0,63})\}|([A-Za-z_][A-Za-z0-9_]{0,63}))(?:/(.*))?', re.S)
PATH_BAD = re.compile(r'[\x00-\x1f\x7f\\]')


def resolve_path(value, *, etc_dir=ETC_DIR, log_dir=LOG_TARGET, env=None):
    """The absolute path a file setting of this device means to its broker, normalised lexically (nothing is followed or
    read), or None when it cannot be told: not text, control characters, a `..`, a `$NAME` this device's broker would not be
    able to resolve. The broker resolves a leading `$NAME/` or `${NAME}/` from its environment (emqx_schema.erl:3466-3503:
    `etc_dir` is the broker's EMQX_ETC_DIR, `log_dir` its EMQX_LOG_DIR, `env` the rest of its Quadlet's EMQX_* settings), a
    `file://` secret takes the path after it, and a relative path is relative to /opt/emqx (BASE_DIR)."""
    text = _text_path(value)
    if text is None or not text or len(text) > 4096 or PATH_BAD.search(text):
        return None
    if text.startswith('file://'):
        text = text[len('file://'):]
    if text.startswith('$'):
        match = PATH_ENV.fullmatch(text)
        if match is None:
            return None
        name = match.group(1) or match.group(2)
        base = {'EMQX_ETC_DIR': etc_dir, 'EMQX_LOG_DIR': log_dir}.get(name) or (env or {}).get(name)
        if not isinstance(base, str) or not base.startswith('/') or '$' in base or PATH_BAD.search(base):
            return None
        text = base.rstrip('/') + '/' + (match.group(3) or '')
    if not text.startswith('/'):
        text = BASE_DIR + '/' + text
    parts = [part for part in text.split('/') if part not in ('', '.')]
    if not parts or '..' in parts:
        return None
    return '/' + '/'.join(parts)


def snapshot_name_ok(name):
    """A data-volume file a setting names that may be carried: a normalised relative name that is not the database
    (`mnesia/`) and not what the converted volume leaves out anyway (DROPPED: generated configs, backups, traces)."""
    return (isinstance(name, str) and ha_odoo._norm(name) == name and name.split('/', 1)[0] != 'mnesia'
            and DROPPED.fullmatch(name) is None)


def mount_targets(mounts, secrets=()):
    """The places of the candidate's filesystem that are this device's own mounts (host files and folders, mounted secrets):
    the candidate gets them exactly as this device has them."""
    targets = set()
    for item in mounts or ():
        if len(item) == 3 and isinstance(item[1], str) and item[1].startswith('/'):
            targets.add(item[1].rstrip('/') or '/')
    for spec in secrets or ():
        try:
            target = tempctr.secret_mount_path(spec)
        except (AttributeError, TypeError, ValueError):
            continue
        if target:
            targets.add(target)
    return targets


def _under(path, roots):
    return any(path == root or path.startswith(root.rstrip('/') + '/') for root in roots)


def _file_key(key):
    """Whether a setting of this name holds a file: the ones EMQX names so (`certfile`, `keyfile`, `cacertfile`, `dhfile`,
    `bootstrap_file`, `init_file`, `crash_dump_file`, `config_files`, `filename`) and anything else that ends in `file` or
    `files`. `path` is judged by what it sits in (file_scan)."""
    name = key.lower() if isinstance(key, str) else ''
    return name == 'filename' or name.endswith(('file', 'files'))


def file_scan(config, *, etc_dir=ETC_DIR, log_dir=LOG_TARGET, env=None, mounts=(), secrets=()):
    """HAOS parity (E-23, E-24, E-29, E-30, E-32, E-35, E-36, E-50): EVERY setting of this device, whatever its root, is looked
    at for the files it names, instead of reviewed lists of roots and fields. A setting names a file when its name says so
    (_file_key; `path` of an authorization source of type `file`; the log handlers' and the crash dump's output paths -- the
    value may then be relative, `data/authz/acl.conf`, the form the Dashboard writes) or its value is an absolute path into
    the data directory (`/opt/emqx/data/…`) or a `file://` secret. Where the file is decides what the candidate needs
    (resolve_path):

    * in the data volume: it is carried, so the snapshot takes it (`data`: relative names);
    * on one of this device's mounts (a host file or folder, a secret) or anywhere else in the image: the candidate has it
      the way this device has it; nothing to carry;
    * where it exists only while a broker runs (/proc, /tmp ...), below the data volume's database, or at a place that cannot
      be told (an environment variable this device's broker would not resolve, a `..`): it cannot be carried, the setting
      is named (`not_carried`: setting names, never a path or a value) and the import goes on;
    * output paths (log files, the crash dump) are never read: `outputs` (absolute) tells where EMQX writes.

    The bootstrap files of the authenticators are bootstrap_references' (E-48, E-49). Returns {'data', 'outputs',
    'not_carried'} (sets). Nesting deeper than 32 levels stops the app, as ever."""
    found = {'data': set(), 'outputs': set(), 'not_carried': set()}
    targets = mount_targets(mounts, secrets)
    authentication = config.get('authentication')
    entries = authentication if isinstance(authentication, list) else []

    def visit(value, path, parent, depth):
        if depth > 32:
            raise BackupError('incompatible', 'EMQX 設定巢狀層級超過限制。')
        text = _text_path(value)
        if text is not None:
            leaf(text, path, parent)
        elif isinstance(value, dict):
            for key, item in value.items():
                visit(item, path + (str(key)[:60],), value, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, path, parent, depth + 1)

    def leaf(text, path, parent):
        key = path[-1] if path else ''
        if not text.strip():
            return   # a file setting left empty (`bootstrap_file = ""`, `init_file = ""`) names nothing
        if key == 'bootstrap_file' and any(parent is entry for entry in entries):
            return   # an authenticator's own bootstrap file: bootstrap_references (E-48, E-49)
        output = (path[:2] == ('log', 'file') and key == 'path') or (path[:1] == ('node',) and key == 'crash_dump_file')
        named = _file_key(key)
        if key == 'path' and not output:
            named = isinstance(parent, dict) and parent.get('type') == 'file'
        if not (output or named or text.startswith((DATA_PREFIX, 'file://'))):
            return   # (a relative `data/…` is a path only where the setting says it names a file: `data/#` can be a topic)
        resolved = resolve_path(text, etc_dir=etc_dir, log_dir=log_dir, env=env)
        name = '.'.join(path)[:120]
        if output:
            if resolved is not None:
                found['outputs'].add(resolved)
        elif resolved is None:
            found['not_carried'].add(name)
        elif resolved.startswith(DATA_PREFIX):
            relative = resolved[len(DATA_PREFIX):]
            if snapshot_name_ok(relative):
                found['data'].add(relative)
            else:
                found['not_carried'].add(name)
        elif _under(resolved, targets):
            return
        elif _under(resolved, RUNTIME_DIRS):
            found['not_carried'].add(name)

    for root, value in config.items():
        visit(value, (str(root)[:60],), config, 1)
    return found


def scratch_plan(outputs, log_dir, mounts=()):
    """E-23, E-35: where the candidate has to be able to write besides its data and log volumes -- the folders of the log files
    and the crash dump (`outputs`, absolute paths) and EMQX_LOG_DIR (`log_dir`) -- when this device keeps them elsewhere (the
    bin/emqx script and the log handlers do not start without a writable log folder). The candidate's own log volume is
    mounted there as scratch space: logs are not carried (what the converted backup holds of the log volume is only its top
    folder). Returns (folders to give it, mount targets of this device's that give way to such a folder -- the device's real
    folder is never mounted into the candidate for writing --, folders it cannot be given). A folder below a mount of this
    device's, anywhere in /opt/emqx (the image's own files) or in a place that is not one of SCRATCH_ROOTS cannot be given."""
    folders = {path.rsplit('/', 1)[0] or '/' for path in outputs}
    if log_dir is not None:
        folders.add(log_dir)
    mount_at = [item[1].rstrip('/') for item in mounts or () if len(item) == 3 and isinstance(item[1], str)]
    extra, give_way, bad = [], [], []
    for folder in sorted(folders):
        if _under(folder, (LOG_TARGET, DATA_TARGET, *WRITABLE_DIRS)):
            continue
        if folder in mount_at:
            extra.append(folder)
            give_way.append(folder)
        elif _under(folder, mount_at):
            bad.append(folder)
        elif (not any(folder.startswith(root + '/') for root in SCRATCH_ROOTS) or _under(folder, (BASE_DIR,))
              or folder.count('/') < 2 or tempctr.TARGET_RE.fullmatch(folder) is None):
            bad.append(folder)
        else:
            extra.append(folder)
    return extra, give_way, bad


DATA_DIR_MOVED = ('EMQX 不能搬過來：這台 EMQX 的資料目錄（node.data_dir）不在 /opt/emqx/data，HA 的資料會放到錯的位置，已停止；'
                  '這台沒有任何改變。')
DATA_DIR_ACTION = '請先把這台 EMQX 的資料目錄改回 /opt/emqx/data（環境變數 EMQX_NODE__DATA_DIR），再匯入 EMQX；其他應用不受影響。'


def check_data_dir(config):
    """E-36: the one node setting that still stops the app -- a data directory that is not this image's, where HA's data
    would land in the wrong place. Every other node setting (extra applications, configuration files, shard transports, the
    etc directory) is this device's own and comes back as it is."""
    node = config.get('node')
    if isinstance(node, dict) and 'data_dir' in node and not ha_emqx_settings.is_data_dir(node['data_dir']):
        raise haissues.stopped(haissues.Issue('emqx.data-dir-moved', 'stop', DATA_DIR_MOVED, action=DATA_DIR_ACTION),
                               'incompatible')


def check_sources(authorization):
    """This device's effective authorization is what the broker answered: a dictionary whose `sources` is a list of dictionaries,
    a file source with a path that is text. What is none of that is not a setting to carry but an answer that cannot be
    read: only this app stops (E-25's rule, and the one thing of the old authorization checks that stays)."""
    if not isinstance(authorization, dict) or not isinstance(authorization.get('sources'), list):
        raise BackupError('incompatible', '無法取得目標 EMQX 的有效授權來源。')
    for source in authorization['sources']:
        if not isinstance(source, dict):
            raise BackupError('incompatible', '無法取得目標 EMQX 的有效授權來源。')
        if source.get('type') == 'file':
            path = ascii_path(source.get('path'))
            if not path or '\x00' in path:
                raise BackupError('incompatible', '目標 EMQX 的 ACL 路徑無效。')


def authorization_file_references(authorization, mounts, *, include_cluster=True, observe=None, etc_dir=None, log_dir=None,
                                  secrets=(), found=None):
    """The data-volume files this device's own authorization sources (an already-decoded effective authorization object) and
    every other setting inside it name, as relative names, with `configs/cluster.hocon` when `include_cluster`. HAOS parity
    (D0): HA's authorization replaces this device's after the import, so this device's sources are not judged -- not their
    types (E-26, E-27), not their fields (E-31), and, with the generic scan (file_scan), not where their files are either
    (E-29, E-30): a file in the data volume is carried wherever in it it lies, one on a mount or in the image is the
    candidate's the way it is this device's, one that cannot be told is only named (`found['not_carried']`). A path may be the
    list of character codes EMQX makes of it (E-28) and may start with the vendor's `${EMQX_ETC_DIR}`. What stays refused is
    what is no authorization at all: sources that are no list, a file source without a path or with a path that is no text.
    Host paths are never read here."""
    check_sources(authorization)
    scan = file_scan({'authorization': authorization}, etc_dir=ETC_DIR if etc_dir is None else etc_dir,
                     log_dir=LOG_TARGET if log_dir is None else log_dir, mounts=mounts, secrets=secrets)
    if found is not None:
        found.update(scan)
    return scan['data'] | ({'configs/cluster.hocon'} if include_cluster else set())


def snapshot_target_volume(work, app, volume, staging, required, *, absent=(), missing=None):
    """Export the target volume and stage only explicitly enumerated configuration references.

    A caller must first establish the complete effective reference list. This helper is not an
    authorization to import: the public preservation blocker remains in place.
    """
    raw = staging / 'emqx-target-config-source.tar'
    snapshot = staging / 'emqx-target-config-snapshot.tar'
    try:
        hacommon.live_export(work, app, volume, raw)
        target_config_snapshot(raw, snapshot, required, absent=absent, missing=missing)
    finally:
        if raw.exists():
            raw.unlink()
    return snapshot


def import_target_snapshot(tmp, snapshot_path, ids):
    """Seed private files AND writable parent directories for the verified image user.

    Podman otherwise creates implicit tar parents as root, preventing the broker from
    writing generated config even when cluster.hocon itself has the correct owner.
    """
    if len(ids) != 2 or any(type(value) is not int or value < 0 for value in ids):   # E-56: root (0) is an owner, too
        raise BackupError('incompatible', '無法確認 EMQX 候選的檔案擁有者。')
    def produce(out):
        parents = {'.'}
        with tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT) as dest:
            dest.addfile(hacommon.info('.', 'dir', mode=0o700, uid=ids[0], gid=ids[1], mtime=0))
            with ha_odoo._live_tar(snapshot_path, '目標 EMQX 設定快照') as source:
                for member in source:
                    name = ha_odoo._norm(member.name)
                    if not name or not member.isfile() or name != member.name or not snapshot_name_ok(name):
                        raise BackupError('incompatible', 'EMQX 設定快照含有不支援的項目。')
                    parts = name.split('/')
                    for depth in range(1, len(parts)):
                        parent = '/'.join(parts[:depth])
                        if parent not in parents:
                            dest.addfile(hacommon.info(parent, 'dir', mode=0o700, uid=ids[0], gid=ids[1], mtime=0))
                            parents.add(parent)
                    info = ha_odoo._copy_info(member, name)
                    info.uid, info.gid, info.mode = ids[0], ids[1], 0o600
                    info.uname = info.gname = ''
                    dest.addfile(info, source.extractfile(member))
    tmp.volume_import('emqx-new', produce)


# Fixed expression: no configuration or credential is interpolated into argv.
CONFIG_EXPR = ('io:format("WOOWCFG:~s:END~n", '
               '[base64:encode(emqx_utils_json:encode(emqx:get_raw_config([])))]).')
# The same configuration in the form a boot of the same files gives it. EMQX 5.8.9 stores
# fill_defaults_for_all_roots(...) as the raw configuration at boot (emqx_config.erl:341,345) but a change made at
# runtime (the Dashboard, the REST API, `conf load`) stores the new raw value without defaults: a built-in database
# source added in the Dashboard reads `max_rules` only after a restart. fill_defaults/1 (exported, :32, :487-505) is
# not idempotent on every root (`retainer`), so comparisons across a boot compare THIS form on both sides (boot_form).
BOOT_CONFIG_EXPR = ('io:format("WOOWCFG:~s:END~n", '
                    '[base64:encode(emqx_utils_json:encode(emqx_config:fill_defaults(emqx:get_raw_config([]))))]).')


def read_effective_config(execute, *, allow_authz_omission=False, _native_digest=None, _expr=CONFIG_EXPR):
    """Read merged RAW broker config, not cooked schema-expanded defaults.

    CONFIG_EXPR calls get_raw_config; retain every returned field unchanged so
    restricted source validators can reject unknown/expanded shapes. Never expose
    the body in errors.
    """
    try:
        if _expr not in (CONFIG_EXPR, BOOT_CONFIG_EXPR):
            raise ValueError()
        result = execute(['emqx', 'eval', _expr])
        body = result.stdout or b''
        if result.returncode or len(body) > MAX_HOCON or not body.startswith(b'WOOWCFG:'):
            raise ValueError()
        encoded, tail = body[8:].split(b':END', 1)
        if tail.strip() not in (b'', b'ok'):
            raise ValueError()
        native_json = base64.b64decode(encoded, validate=True)
        config = util.loads_strict(native_json, max_bytes=MAX_HOCON)
        if not isinstance(config, dict) or not config or not isinstance(config.get('authorization'), dict):
            raise ValueError()
        auth = config['authorization']
        if type(allow_authz_omission) is not bool:
            raise ValueError()
        for key, allowed in (('no_match', ('allow','deny')), ('deny_action', ('ignore','disconnect'))):
            if key not in auth and allow_authz_omission:
                continue
            if auth.get(key) not in allowed:
                raise ValueError()
        if _native_digest is not None:
            if type(_native_digest) is not list or _native_digest: raise ValueError()
            _native_digest.append(hashlib.sha256(native_json).hexdigest().upper())
        return config
    except (BackupError, ValueError, TypeError, RecursionError):
        raise BackupError('incompatible', '無法安全取得 EMQX 有效設定，已停止。') from None


def boot_form(execute):
    """A running broker's configuration as a boot of the same files gives it (BOOT_CONFIG_EXPR): compared on both sides
    wherever a boot stands between them (this device -> the candidate booted from its snapshot; the conversion's
    candidate -> the restored broker). Every other check keeps the plain raw configuration."""
    return read_effective_config(execute, _expr=BOOT_CONFIG_EXPR)


# Fixed expression: a running broker's scheduler threads (total, online). EMQX 5.8.9 derives schema defaults from them
# and a boot stores those in the raw configuration (emqx_config.erl:341,345): dashboard.listeners.{http,https}.
# num_acceptors = schedulers_online (emqx_dashboard_schema.erl:125-131), node.broker_pool_size = 2 x schedulers and
# generic_pool_size = schedulers (emqx_conf_schema.erl:688-706, emqx_vm.erl:174-175). The candidate runs with fewer CPUs
# (tempctr --cpus), so the VM gives it fewer online schedulers (dev-d 2026-11-24 attempt-08: `dashboard` differed); it
# therefore starts with this device's counts: ERL_AFLAGS "+S total:online" (erlexec puts it at the START of the
# command line). Not ERL_FLAGS: erlexec appends that after bin/emqx's trailing `-emqx_data_dir <dir>`, which bin/emqx
# then reads back from `ps -ef` for every ctl/eval command (bin/emqx:570, :1321-1324 "order matters"): the data dir
# became "/opt/emqx/data --", mkdir failed on the read-only root, `emqx ctl status` never answered (dev-d 2026-11-24
# attempt-10; reproduced in the lab store).
VM_EXPR = ('io:format("WOOWVM:~b:~b:END~n", '
           '[erlang:system_info(schedulers), erlang:system_info(schedulers_online)]).')
MAX_SCHEDULERS = 1024


def schedulers(execute):
    """(total, online) scheduler threads of a running broker (VM_EXPR); anything else refuses."""
    try:
        result = execute(['emqx', 'eval', VM_EXPR])
        body = result.stdout or b''
        if result.returncode or not body.startswith(b'WOOWVM:'):
            raise ValueError()
        counts, tail = body[7:].split(b':END', 1)
        if tail.strip() not in (b'', b'ok'):
            raise ValueError()
        match = re.fullmatch(rb'([1-9][0-9]{0,3}):([1-9][0-9]{0,3})', counts)
        total, online = int(match.group(1)), int(match.group(2))
        if not online <= total <= MAX_SCHEDULERS:
            raise ValueError()
        return total, online
    except (BackupError, ValueError, TypeError, AttributeError):
        raise BackupError('incompatible', '無法安全取得 EMQX 的執行環境（排程器數量），已停止。') from None


def bootstrap_references(config, mounts, secrets, *, lost=None):
    """Only built-in password database bootstrap files from existing explicit mounts.

    Podman mounts secret payloads directly. Never export them into staging or evidence.
    Relative paths and environment interpolation are intentionally unsupported here.

    E-48, E-49: with `lost` (a list) an authenticator whose bootstrap file is of a kind or at a place that cannot be
    followed (an unsupported type or path, no unique read-only mount, a secret that is not a restricted file mount) is not
    refused: its reason is appended to `lost` and it is left out (the import goes on and a notice says this device's
    pre-created MQTT accounts may have to be made again). Without `lost` it stops, as before.
    """
    authn = config.get('authentication', [])
    if not isinstance(authn, list):
        raise BackupError('incompatible', 'EMQX 帳號驗證設定格式不受支援。')
    paths = set()
    for authenticator in authn:
        if not isinstance(authenticator, dict):
            raise BackupError('incompatible', 'EMQX 帳號驗證設定格式不受支援。')
        path = authenticator.get('bootstrap_file', '')
        if path == '':
            continue
        try:
            paths.add(_bootstrap_path(authenticator, path, mounts, secrets))
        except BackupError:
            if lost is None:
                raise
            lost.append(path if isinstance(path, str) else '')
    return paths


def _bootstrap_path(authenticator, path, mounts, secrets):
    if (authenticator.get('mechanism') != 'password_based' or
            authenticator.get('backend') != 'built_in_database' or
            authenticator.get('bootstrap_type', 'plain') not in ('plain', 'hash') or
            not isinstance(path, str) or not path.startswith('/') or
            ha_odoo._norm(path[1:]) != path[1:] or '$' in path):
        raise BackupError('incompatible', 'EMQX bootstrap 類型或路徑不受支援。')
    matches = 0
    for source, target, options in mounts:
        if target == path:
            if options != 'ro' or not source.startswith('/'):
                raise BackupError('incompatible', 'EMQX bootstrap 必須使用既有唯讀掛載。')
            matches += 1
    for spec in secrets:
        parts = spec.split(',')
        if not tempctr.SECRET_NAME_RE.fullmatch(parts[0]):
            raise BackupError('incompatible', 'EMQX secret 宣告無效。')
        options = {}
        for part in parts[1:]:
            key, sep, value = part.partition('=')
            if not sep or key in options or not tempctr.SECRET_OPTION_RE.fullmatch(part):
                raise BackupError('incompatible', 'EMQX secret 宣告無效或重複。')
            options[key] = value
        if options.get('target') != path:
            continue
        if options.get('type', 'mount') != 'mount' or options.get('mode') not in ('0400', '0440', '400', '440'):
            raise BackupError('incompatible', 'EMQX bootstrap secret 必須是限權檔案掛載。')
        matches += 1
    if matches != 1:
        raise BackupError('incompatible', 'EMQX bootstrap 未對應唯一的既有掛載。')
    return path


# Exact files named by emqx_schema:cert_file/2 in 5.8.9. Other substitutions are rejected.
IMAGE_TLS_FILES = {prefix + name: '/opt/emqx/etc/certs/' + name
                   for prefix in ('${EMQX_ETC_DIR}/certs/', '/opt/emqx/etc/certs/')
                   for name in ('cacert.pem', 'cert.pem', 'key.pem')}


def image_tls_references(config):
    paths = set()
    def visit(value, depth=0):
        if depth > 32:
            raise BackupError('incompatible', 'EMQX 設定巢狀層級超過限制。')
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('certfile', 'keyfile', 'cacertfile', 'dhfile') and isinstance(item, str):
                    if item in IMAGE_TLS_FILES:
                        paths.add(IMAGE_TLS_FILES[item])
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
    visit(config)
    return paths


def tls_fingerprints(execute, paths):
    """{path: sha256 hex} of the image's own TLS files the settings name. E-54: one that cannot be read is left out (the
    comparison of the candidate's with this device's certificate is then skipped for it; the caller logs it); a path that
    is not one of the image's files is still refused."""
    result = {}
    for path in sorted(paths):
        if path not in IMAGE_TLS_FILES.values():
            raise BackupError('incompatible', 'EMQX 映像憑證路徑不受支援。')
        response = execute(['sha256sum', path])
        raw = response.stdout or b''
        if response.returncode or len(raw) > 1024 or not re.fullmatch(
                rb'[0-9a-f]{64}  ' + re.escape(path.encode()) + rb'\n', raw):
            continue
        result[path] = raw[:64]
    return result


def configuration_references(config, mounts, secrets=(), *, include_cluster=True, observe=None, etc_dir=None,
                             lost=None, log_dir=None, env=None, found=None):
    """The data-volume files this device's configuration names, as relative names (with `configs/cluster.hocon` when
    `include_cluster`). HAOS parity: no root and no field is judged against a reviewed list any more (E-32 unknown roots,
    E-33 and E-34 unlisted fields, E-37 rpc, E-39 log handlers, E-40 a bootstrap field that is no text, E-45 Prometheus,
    E-46 the system monitor, E-41..E-44 and E-47 what this device has of its own: ha_emqx_settings.own_items says those); the
    candidate starts with exactly this device's configuration and every setting is scanned for the files it names (file_scan:
    E-23, E-24, E-29, E-30, E-35, E-36, E-50). What still stops the app: a data directory that is not the image's (E-36), a
    clustered broker (E-38, not this lane's), a nesting deeper than 32 levels, and the bootstrap rules of bootstrap_references
    (without `lost`). `found` (a dict) gets the scan's `data`, `outputs` and `not_carried`."""
    check_data_dir(config)
    ha_emqx_settings.validate(config, mounts)
    check_sources(config.get('authorization'))
    bootstrap_references(config, mounts, secrets, lost=lost)
    scan = file_scan(config, etc_dir=ETC_DIR if etc_dir is None else etc_dir, log_dir=LOG_TARGET if log_dir is None else log_dir,
                     env=env, mounts=mounts, secrets=secrets)
    if found is not None:
        found.update(scan)
    return scan['data'] | ({'configs/cluster.hocon'} if include_cluster else set())


OVERRIDE_STATE_EXPR = ('D=file:read_link_info("/opt/emqx/data/configs"), '
    'F=file:read_link_info("/opt/emqx/data/configs/cluster.hocon"), '
    'S=case {D,F} of {{error,enoent},{error,enoent}} -> <<"parent-absent">>; '
    '{{ok,Dir},{error,enoent}} when element(3,Dir)=:=directory -> <<"absent">>; '
    '{{ok,Dir},{ok,File}} when element(3,Dir)=:=directory, element(3,File)=:=regular, '
    'element(9,File)=:=1, element(2,File)=<8388608 -> <<"present">>; _ -> <<"refused">> end, '
    'io:format("WOOWOVERRIDE:~s:END",[S]).')


def target_override_state(execute):
    """Fixed no-follow metadata proof; never read or invent override contents."""
    result=execute(['emqx','eval',OVERRIDE_STATE_EXPR])
    raw=(result.stdout or b'').strip()
    if result.returncode==0:
        for state in ('present','absent','parent-absent'):
            if raw==b'WOOWOVERRIDE:'+state.encode()+b':ENDok':return state
    raise BackupError('incompatible', '無法驗證 EMQX 原始覆寫設定檔，已停止。')


def target_etc_dir(execute):
    """EMQX_ETC_DIR of a running broker (fixed eval, nothing interpolated). E-24: whatever directory the broker says is the one
    the vendor's `${EMQX_ETC_DIR}` means (emqx_schema.erl:3466-3503 resolves it with os:getenv); the candidate starts with the
    same environment, so it is the candidate's too, and this device's ACL file is looked for there. Only an answer that is no
    plain absolute directory is no answer. An empty one (the variable is not set: the vendor script exports it, so the image
    does not do this) is the image's ETC_DIR."""
    result = execute(['emqx', 'eval', ETC_EXPR])
    raw = (result.stdout or b'').strip()
    match = (re.fullmatch(rb'WOOWETC:([^\x00-\x1f\x7f]{0,1024}):END(?:ok)?', raw)
             if result.returncode == 0 and len(raw) <= 4096 else None)
    if match is not None:
        text = match.group(1).decode('utf-8', 'replace')
        if not text:
            return ETC_DIR
        resolved = resolve_path(text, etc_dir=None, log_dir=None) if text.startswith('/') and '$' not in text else None
        if resolved is not None and resolved == (text.rstrip('/') or '/'):
            return resolved
    raise BackupError('incompatible', '無法安全取得 EMQX 有效設定，已停止。')


def target_running(work, app, target):
    result = work.runner(app).podman('container', 'inspect', '--format', '{{.State.Running}}', target.container,
                                     timeout=60, max_output=1024, check=False)
    return result.returncode == 0 and (result.stdout or b'').strip() == b'true'


def broker_ready(runner, container):
    """`ready` of hatarget.ensure_running for this device's broker: it answers `emqx ctl status` (not only runs)."""
    result = runner.podman('exec', container, 'emqx', 'ctl', 'status', timeout=60, max_output=64 * 1024, check=False)
    return result.returncode == 0 and b'is started' in (result.stdout or b'')


def ensure_target_running(work, app, target):
    """E-22 (CM-07): this device's EMQX that is stopped is started to be read and put back when the app's throwaway
    objects are cleaned up; only when it cannot be started (or does not get ready) does this app stop, with the reason."""
    if callable(getattr(work, 'temp', None)):   # a real job: the put-back needs the app's throwaway objects
        hatarget.ensure_running(work, app, target.container, ready=broker_ready)


def device_log_dir(target):
    """The folder this device's `${EMQX_LOG_DIR}` is: its Quadlet's EMQX_LOG_DIR, else the image's LOG_TARGET (E-23); None
    when that setting is no plain absolute folder."""
    env = getattr(target, 'env', None)
    value = env.get('EMQX_LOG_DIR') if isinstance(env, dict) else None
    if not value:
        return LOG_TARGET
    return resolve_path(value, etc_dir=None, log_dir=None) if isinstance(value, str) and value.startswith('/') else None


def target_static(work, app, target, execute, *, observe=None, lost=None, notes=None):
    """The read-only part of this device's preflight, shared by the check and the conversion: the effective RAW
    configuration, its file references and the override state. HAOS parity (D0): this device's authorization sources are no
    longer judged (E-26, E-27, E-31); HA's replace them. Nor are its etc and log directories (E-23, E-24: the candidate has
    the same environment, and the vendor's `${EMQX_ETC_DIR}` is looked up where this device's broker says it is) or the
    places its files are in (file_scan). `lost`: see bootstrap_references. `notes` (a dict) gets `etc_dir`, `log_dir` and the
    scan's findings (`scan`)."""
    def stage(name):
        if observe is not None:observe(name)
    stage('target_config')
    try:
        original=read_effective_config(execute)
    except BackupError:
        if not target_running(work, app, target):
            raise BackupError('incompatible', NOT_RUNNING) from None
        raise
    etc=target_etc_dir(execute)
    log_dir=device_log_dir(target)
    stage('target_references')
    scan={}
    explicit=configuration_references(original,target.files,target.secrets,include_cluster=False,observe=observe,
                                      etc_dir=etc,lost=lost,log_dir=log_dir,env=getattr(target,'env',None),found=scan)
    state=target_override_state(execute)
    if notes is not None:
        notes.update(etc_dir=etc,log_dir=log_dir,scan=scan)
    return original,explicit,state


CAPTURE_ATTEMPTS = 3
CONFIG_CHANGING = '這台 EMQX 的設定一直在變動（有人正在修改它），讀不到穩定的設定；這台沒有任何改變。'


def capture_target_seed(work, app, target, staging, *, notes=None):
    """Exact product target preflight, including explicitly proven absence.

    A missing cluster override is permitted only when no effective dependency
    references it and no-follow metadata plus COMPLETE volume traversal prove
    its absence. No empty override file is fabricated. All other files remain
    mandatory except a file the settings name that is not there (E-55: said in `notes['missing']`, the candidate starts
    without it as this device's own broker has); effective configuration/state are re-read before candidate boot, and
    when they changed meanwhile the whole read is made again (E-58, up to CAPTURE_ATTEMPTS times: `notes['rereads']`).
    Only a configuration that keeps changing stops the app (`emqx.config-changing`). `notes['lost']`: the reasons a
    bootstrap file of this device could not be followed (E-48, E-49). HAOS parity: the files are those of the generic scan
    of every setting (file_scan); `notes` also gets `etc_dir` and `log_dir` (this device's, E-23, E-24), `unreached` (the
    settings whose files cannot be carried, E-29, E-30, E-50), `scratch` and `scratch_drop` (the folders the candidate is
    given for what EMQX writes, E-35) and `dirs` (the names of this device's own non-default folders). A place for the
    log or the crash dump that the candidate cannot be given stops only this app (`emqx.output-dir-unusable`).
    """
    observe=getattr(work,'_emqx_build_stage',None)
    def stage(name):
        if observe is not None:observe(name)
    def execute(command):
        return work.runner(app).podman('exec', target.container, *command, timeout=120,
                                      max_output=MAX_HOCON, check=False)
    for attempt in range(1, CAPTURE_ATTEMPTS + 1):
        if callable(getattr(work, 'checkpoint', None)):
            work.checkpoint()
        lost, missing, seen = [], [], {}
        original,explicit,state=target_static(work,app,target,execute,observe=observe,lost=lost,notes=seen)
        scan=seen.get('scan') or {}
        extra,give_way,bad=scratch_plan(scan.get('outputs', ()),seen.get('log_dir'),target.files)
        if bad:
            raise haissues.stopped(haissues.Issue('emqx.output-dir-unusable', 'stop', OUTPUT_DIR_UNUSABLE, sorted(bad),
                                                  action=OUTPUT_DIR_ACTION), 'incompatible')
        absent=({'configs/cluster.hocon'} if state in ('absent','parent-absent')
                and 'configs/cluster.hocon' not in explicit else set())
        required=explicit | {'configs/cluster.hocon'}
        stage('target_tls');fingerprints=tls_fingerprints(execute,image_tls_references(original))
        stage('target_snapshot')
        snapshot=snapshot_target_volume(work,app,target.data_volume,staging,required,absent=absent,missing=missing)
        if 'configs/cluster.hocon' in missing:   # the override file's own state was proven by metadata: this is no "file named but not there"
            os.unlink(snapshot)
            raise BackupError('incompatible', '目標 EMQX 設定參照的檔案不存在，已停止。')
        stage('target_consistency')
        if target_override_state(execute)==state and read_effective_config(execute)==original:
            if notes is not None:
                dirs=sorted({path for path in (seen.get('etc_dir'),seen.get('log_dir'),*extra) if path
                             and path not in (ETC_DIR,LOG_TARGET)})
                notes.update(lost=lost, missing=missing, rereads=attempt - 1, etc_dir=seen.get('etc_dir', ETC_DIR),
                             log_dir=seen.get('log_dir', LOG_TARGET), unreached=sorted(scan.get('not_carried', ())),
                             scratch=extra, scratch_drop=give_way, dirs=dirs)
            return original,snapshot,fingerprints
        os.unlink(snapshot)
        if attempt < CAPTURE_ATTEMPTS:
            time.sleep(2)
    raise haissues.stopped(haissues.Issue('emqx.config-changing', 'stop', CONFIG_CHANGING,
                                          action='請先不要在這台 EMQX 的管理頁修改設定，等修改完成後再匯入。'),
                           'incompatible', app=getattr(app, 'id', app))


def candidate_from_target(work, app, tmp, target, staging, export, ids, *, hint='', readings=None, notes=None):
    """This device's capture (capture_target_seed) and the candidate built from it: the public conversion's path."""
    notes = {} if notes is None else notes
    original,snapshot,fingerprints=capture_target_seed(work,app,target,staging,notes=notes)
    # This device's configuration as its next boot will read it (a source added in the Dashboard since the last
    # restart reads its defaults only then): the candidate, booted from the snapshot, must equal THIS form.
    device=lambda command: work.runner(app).podman('exec', target.container, *command, timeout=120,
                                                   max_output=MAX_HOCON, check=False)
    target_boot=boot_form(device)
    # ... and the candidate starts with this device's scheduler counts, which some of those defaults come from.
    # E-57: a count that cannot be read, or that the candidate does not get, is no reason to stop.
    try:
        target_vm=schedulers(device)
    except BackupError as error:
        if haissues.is_job_wide(error):
            raise
        target_vm=None
    observe=getattr(work,'_emqx_build_stage',None)
    if observe is not None:observe('target_runtime')
    return target_broker(work,tmp,target,export,ids,hint=hint,
        target_snapshot=snapshot,target_config=original,image_fingerprints=fingerprints,target_boot=target_boot,
        target_vm=target_vm,readings=readings,notes=notes)

def candidate_with_effective_acl(work, app, tmp, target, staging, export, ids, authorization, *, hint=''):
    """Stage known file ACL references and seed a candidate; not a complete preservation check.

    The caller must obtain a trusted effective authorization object and independently account
    for references in every other configuration root before using this in a conversion.
    """
    required = authorization_file_references(authorization, target.files)
    snapshot = snapshot_target_volume(work, app, target.data_volume, staging, required)
    return target_broker(work, tmp, target, export, ids, hint=hint, target_snapshot=snapshot)


def preserved_settings(config):
    """This device's operational settings stay; HA's data roots migrate (D0: HA's authentication and authorization with
    them: access_roots)."""
    return {key: value for key, value in config.items() if key not in DATA_ROOTS}


def authn_key(row):
    return row.get('mechanism'), row.get('backend'), row.get('user_id_type', 'username')


def access_roots(after, original, readings, lost_paths):
    """D0 (HAOS parity): what to load into the candidate so that its authentication and authorization are exactly HA's
    after the import, and what became of this device's pre-created accounts.

    EMQX merges HA's roots into this device's (HA's same-named settings win, what only this device has stays), so the
    candidate holds more than HA's: its list of authenticators and authorization sources are cut to HA's, in HA's order,
    each as the candidate holds it (the import made its paths its own); HA's no-match rule and deny action are set
    explicitly (an authorization without them would keep this device's). HA with no authenticator at all is an explicit
    empty list: left alone, the merge would keep this device's and nobody could reach HA's anonymous broker.
    This device's bootstrap file (its own MQTT accounts, e.g. woow) is attached to HA's built-in database authenticator
    of the same identity when that one is enabled and, for a `hash` file, hashes the same way (E-68, E-69); every other
    case leaves it off and says why. Returns ({root: value to load}, {'bootstrap': [reasons], 'removed_builtin':
    bool, 'absent': [HA's authenticators and authorization sources the candidate does not hold]}). `lost_paths`: bootstrap
    files that could not be followed at all (E-48, E-49): left off."""
    changed, facts = {}, {'bootstrap': [], 'removed_builtin': False, 'absent': []}
    rows = after.get('authentication')
    rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    held = {}
    for row in rows:
        held.setdefault((row.get('mechanism'), row.get('backend')), row)
    facts['absent'] += [f"{item['mechanism']}／{item['backend']}" for item in readings['authn']
                        if (item['mechanism'], item['backend']) not in held]
    want = [dict(held[(item['mechanism'], item['backend'])]) for item in readings['authn']
            if (item['mechanism'], item['backend']) in held]
    originals = original.get('authentication')
    for target in originals if isinstance(originals, list) else []:
        path = target.get('bootstrap_file') if isinstance(target, dict) else None
        if not path:
            continue
        if path in lost_paths:
            continue
        matches = [row for row in want if authn_key(row) == authn_key(target)]
        if len(matches) != 1 or matches[0].get('enable', True) is not True:
            facts['bootstrap'].append('ha-authn')
            continue
        row = matches[0]
        if (target.get('bootstrap_type', 'plain') == 'hash'
                and row.get('password_hash_algorithm') != target.get('password_hash_algorithm')):
            facts['bootstrap'].append('hash')
            continue
        row['bootstrap_file'] = path
        row['bootstrap_type'] = target.get('bootstrap_type', 'plain')
    if want != rows:
        changed['authentication'] = want
    current = after.get('authorization') if isinstance(after.get('authorization'), dict) else {}
    sources = [s for s in current.get('sources') or [] if isinstance(s, dict)]
    by_type = {}
    for source in sources:
        by_type.setdefault(source.get('type'), source)
    ha_types = [item['type'] for item in readings['authz']]
    facts['absent'] += [kind for kind in dict.fromkeys(ha_types) if kind not in by_type]
    wanted = [dict(by_type[kind]) for kind in dict.fromkeys(ha_types) if kind in by_type]
    flags = {item['type']: item['enable'] for item in readings['authz']}
    for source in wanted:
        source['enable'] = flags[source['type']]
    new = dict(current)
    new['sources'] = wanted
    if readings.get('strict'):
        new['no_match'], new['deny_action'] = readings['strict']
    if new != current:
        changed['authorization'] = new
    facts['removed_builtin'] = any(s.get('type') == 'built_in_database' and s.get('enable') is True
                                   and 'built_in_database' not in ha_types for s in sources)
    return changed, facts


def apply_ha_access(tmp, read_candidate, readings, original, lost_paths, *, observe=None):
    """D0: make the candidate's authentication and authorization HA's (access_roots), then read them back: they must be
    what was meant (E-80: right after applying, the setting really is HA's, else the app stops). Returns access_roots'
    facts. A built-in database source that HA does not have is first switched off and only then removed: EMQX clears the
    ACL rules (`emqx_acl`) of a source it destroys, not of one that is disabled (5.8.9 emqx_authz), and HA's rows must
    stay (the row counts check it)."""
    after = read_effective_config(read_candidate, allow_authz_omission=True)
    changed, facts = access_roots(after, original, readings, lost_paths)
    if facts['absent']:
        # Access control is not one of the items E-67 lets an import skip: when one of HA's authenticators or sources is not in
        # the candidate, the list that would be loaded is not HA's, and cutting this device's own to it could leave nobody to
        # log in or everybody in (S2 is HA's own choice, confirmed by name; this is a failed import). Stops only this app.
        raise BackupError('incompatible', 'EMQX 匯入後，HA 的帳號驗證或授權設定（' + hacommon.names(facts['absent'], 8)
                          + '）沒有出現在暫用的 EMQX 裡，已停止；這台沒有任何改變。請在 HA 先停止 EMQX 附加元件，重新備份後再匯入；'
                            '如果仍然一樣，請把這份備份交給支援人員檢查。')
    if changed:
        if observe is not None:
            observe('access_apply')
        if facts['removed_builtin'] and 'authorization' in changed:
            switched = json.loads(json.dumps(after['authorization']))
            for source in switched.get('sources', []):
                if isinstance(source, dict) and source.get('type') == 'built_in_database':
                    source['enable'] = False
            load_roots(tmp, {'authorization': switched})
        load_roots(tmp, changed)
    final = read_effective_config(read_candidate, allow_authz_omission=True)
    authorization = final.get('authorization') if isinstance(final.get('authorization'), dict) else {}
    kinds = [(s.get('type'), s.get('enable', True)) for s in authorization.get('sources') or [] if isinstance(s, dict)]
    ha_kinds = [(item['type'], item['enable']) for item in readings['authz'] if
                item['type'] in {s.get('type') for s in authorization.get('sources') or [] if isinstance(s, dict)}]
    strict = (authorization.get('no_match'), authorization.get('deny_action'))
    # What is compared is what was meant -- which authenticators, enabled or not, and where this device's bootstrap file is
    # attached -- not whole rows: `conf load` stores a root with its schema defaults filled (emqx_conf_cli.erl:541-546).
    want = changed.get('authentication', after.get('authentication'))
    if (_authenticators(final.get('authentication')) != _authenticators(want)
            or _bootstraps(final.get('authentication')) != _bootstraps(want) or kinds != ha_kinds
            or (readings.get('strict') and strict != tuple(readings['strict']))):
        raise BackupError('incompatible', 'EMQX 匯入後，帳號驗證或授權沒有成為 HA 的設定，已停止；這台沒有任何改變。')
    return facts


def _authenticators(rows):
    """[(mechanism, backend, enabled)] of a list of authenticators, in order."""
    return [(row.get('mechanism'), row.get('backend'), row.get('enable', True)) for row in rows or ()
            if isinstance(row, dict)] if isinstance(rows, list) else []


def _bootstraps(rows):
    """{(mechanism, backend): bootstrap file} of the authenticators that have one."""
    return {(row.get('mechanism'), row.get('backend')): row.get('bootstrap_file') for row in rows or ()
            if isinstance(row, dict) and row.get('bootstrap_file')} if isinstance(rows, list) else {}


def load_roots(tmp, settings):
    """`emqx ctl conf load --replace` of whole roots in the candidate: the value goes in on stdin into a private file of the
    candidate's own volume; nothing about it reaches a command line or a log."""
    snippet = json.dumps(settings, ensure_ascii=True).encode()
    try:
        written = tmp.exec('emqx-new', ['sh', '-c', f'umask 077; cat > {WORK}/in/target-settings.hocon'],
                           input=snippet, timeout=120, max_output=64 * 1024, check=False)
        if written.returncode:
            raise ValueError()
        loaded = ctl(tmp, 'emqx-new', ['conf', 'load', '--replace', f'{WORK}/in/target-settings.hocon'],
                     timeout=600, check=False)
        if loaded.returncode:
            raise ValueError()
    except (BackupError, ValueError):
        raise BackupError('incompatible', '無法恢復 EMQX 目標設定，已停止。') from None


def restore_target_settings(tmp, original, read_candidate, *, observe=None, original_boot=None):
    """Replace changed target setting roots, not merge stale/imported fields into them.

    HAOS parity (D0): only this device's own operational roots (listeners, dashboard, node, log, ...: everything that is
    not one of HA's DATA_ROOTS) are loaded back; authentication and authorization are HA's (apply_ha_access), so nothing
    of this device's authorization is preserved, switched off or written back any more.
    Roots absent on the target cannot be restored by guessing an empty/default value.
    Any such extra operational root remains a failure until removal is implemented.
    `original_boot`: this device's configuration in its boot form (boot_form); a root loaded back must equal it there.
    """
    before = read_effective_config(read_candidate, allow_authz_omission=True)
    expected = preserved_settings(original)
    actual = preserved_settings(before)
    if set(actual) - set(expected):
        raise BackupError('incompatible', 'EMQX 匯入新增了無法安全移除的目標設定，已停止。')
    changed = {key: value for key, value in expected.items() if key not in actual or actual[key] != value}
    if set(changed) & ha_emqx_settings.IMMUTABLE_ROOTS:
        raise BackupError('incompatible', 'EMQX 唯讀啟動設定在匯入後改變，已停止。')
    if changed:
        load_roots(tmp, changed)
    after = read_effective_config(read_candidate)
    want = dict(expected)
    if original_boot is not None:
        # `emqx ctl conf load` stores every root it loads with its schema defaults filled (emqx_conf_cli.erl:350-353,
        # 541-546), per root as fill_defaults/1 does (emqx_config.erl:487-505): a loaded root of this device equals its
        # boot form, not its plain raw form when it was changed at runtime (dev-d 2026-11-24 attempt-11: the
        # 「內建資料庫」 source added in the Dashboard lacks `max_rules` until a restart).
        want.update({key: original_boot[key] for key in changed if key in want and key in original_boot})
    kept = preserved_settings(after)
    differ = sorted(key for key in set(kept) | set(want) if kept.get(key) != want.get(key))
    if differ:   # root names only (schema keys), never values
        raise BackupError('incompatible', f'EMQX 匯入後未能保留目標有效設定（{hacommon.names(differ, 8)}），已停止。')


# ---------------------------------------------------------------------- what could hurt the customer (S1, D4)
# HAOS restores HA's EMQX settings as they are. This device differs from HAOS in one way that can hurt: its own MQTT
# account file and its environment (the Dashboard password, the node cookie) are in the same container. So HA's settings
# run as they are and the customer is shown, by name, those that can read this device's files or environment or receive
# client credentials ("import only backups you trust"). The same functions look at the candidate's finished configuration
# in the check and in the conversion, so the names (and with them the confirmation key) are the same.

def _text_of(value):
    if isinstance(value, str):
        return value
    if (isinstance(value, list) and value and len(value) <= 65536
            and all(type(v) is int and 0 < v < 0x110000 for v in value)):
        return ''.join(map(chr, value))
    return None


def _dotted(parts):
    return '.'.join(str(part)[:60] for part in parts)


def _names_of(config, only, match):
    """Where, in the DATA_ROOTS named in `only`, a text `match` accepts is found: sorted (root, first key, second key)
    tuples; a text deeper than 64 levels counts as found (too deep to look at). A dictionary in a list is named by its
    name, id, mechanism:backend or position."""
    found = set()

    def visit(root, path, value, depth=0):
        if depth > 64:
            found.add((root,) + path[:2])
            return
        text = _text_of(value)
        if text is not None:
            if match(text):
                found.add((root,) + path[:2])
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and match(key):
                    found.add((root,) + path[:2])
                visit(root, path + (str(key)[:200],), item, depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    kind = (f'{item["mechanism"]}:{item["backend"]}' if 'mechanism' in item and 'backend' in item
                            else None)
                    visit(root, path + (str(item.get('name') or item.get('id') or kind or item.get('type') or index)[:200],),
                          item, depth + 1)
                else:
                    visit(root, path, item, depth + 1)

    for root in only:
        if root in config:
            visit(root, (), config[root])
    return sorted(found)


FILE_SECRET = ('HA 的 EMQX 設定有 {count} 處用「file://」讀取本機檔案當作密碼（{names}）；它們會照 HA 原樣啟用，匯入後這台的 EMQX '
               '會讀取這台自己的檔案（例如 MQTT 帳號檔或環境變數）並送到這些設定指定的伺服器。請只匯入你信任的備份。')
JQ_RULE = ('HA 的 EMQX 規則有 {count} 條使用 jq 函式（{names}）；EMQX 的 jq 能讀取這台 EMQX 的環境變數（其中有 Dashboard '
           '密碼與節點 cookie 等機密），這些規則會照 HA 原樣啟用，可以把它們發布或送出去。請只匯入你信任的備份。')
CREDENTIAL_RECEIVER = ('HA 的 EMQX 設定有{what}（{names}）；它們會照 HA 原樣啟用，每個連線用戶端的帳號與密碼（包括這台自己服務的'
                       '帳號）都會送到 HA 設定的伺服器。請只匯入你信任的備份。')
AUTHZ_RECEIVER = ('HA 的 EMQX 授權設定有外部來源（{names}）；它們會照 HA 原樣啟用，每次發布或訂閱時的帳號名稱與主題都會送到 HA '
                  '設定的伺服器。請只匯入你信任的備份。')
JQ_CALL = re.compile(r'(?<![A-Za-z0-9_])jq(?![A-Za-z0-9_])', re.IGNORECASE)
BUILTIN_AUTHN = frozenset({('password_based', 'built_in_database'), ('scram', 'built_in_database')})
AUTHN_NAMES = {'http': 'HTTP', 'mysql': 'MySQL', 'postgresql': 'PostgreSQL', 'redis': 'Redis', 'mongodb': 'MongoDB',
               'ldap': 'LDAP', 'jwt': 'JWT', 'cinfo': '用戶端資訊', 'gcp_device': 'GCP 裝置', 'kerberos': 'Kerberos'}


def file_secret_items(config):
    """The settings HA's import brought (DATA_ROOTS except authorization) holding a value that EMQX 5.8.9 loads with its
    `file://` secret loader (emqx_schema_secret.erl:74-77, emqx_secret_loader.erl:28-45: the file is read on THIS device at
    use time, its path even env-interpolated). A migrated connector or authenticator would read this device's bootstrap
    credential mount or /proc/self/environ (its env secrets) and send it to the server HA's settings name (security
    review SR-3, 2026-11-23). Conservative: any string or ASCII charlist that starts with `file://` after leading blanks,
    any case. The names of the settings (`connectors.http.erp`), never a value (E-76)."""
    return [_dotted(found) for found in _names_of(config, [root for root in DATA_ROOTS if root != 'authorization'],
                                                  lambda text: text.lstrip().lower().startswith('file://'))]


def file_secret_roots(config):
    """The ROOTS of file_secret_items (kept for callers that only want to know where)."""
    return sorted({name.split('.', 1)[0] for name in file_secret_items(config)})


def jq_rule_items(config):
    """The rules that name EMQX's jq function. jq runs with the broker's process environment (emqx_rule_funcs.erl:957-980 ->
    jq:process_json; jq('env'), jq('$ENV'), jq('env.NAME') return it, proven in a throwaway 5.8.9 broker), i.e. this
    device's env secrets, and its program may even come from a message at run time, so any use counts (security review
    SR-6, 2026-11-23). Every string under rule_engine is scanned. The rule ids (E-77)."""
    rules = config.get('rule_engine')
    if not isinstance(rules, dict):
        return []
    found = _names_of({'rule_engine': rules}, ['rule_engine'], lambda text: bool(JQ_CALL.search(text)))
    return sorted({(path[2] if len(path) >= 3 and path[1] == 'rules' else _dotted(path[1:3]) or 'rule_engine')
                   for path in found})


def jq_rule_count(config):
    return len(jq_rule_items(config))


def credential_receiver_items(config):
    """What the settings HA's import brought would hand client credentials to (E-78, E-79): an enabled authenticator that
    is not the built-in database (an HTTP one posts `${password}`, JWT/LDAP/SQL/Redis ones query outside) and an enabled
    ExHook server (its client.authenticate hook carries the password: emqx_exhook_handler.erl:104,318-333). This device's
    own services log in through the same chain with the bootstrap users' passwords (security review SR-7, 2026-11-23).
    ({'authn': [names], 'exhook': [server names]}); nothing for the built-in database and no enabled ExHook."""
    names = set()
    authn = config.get('authentication', [])
    for authenticator in authn if isinstance(authn, list) else [None]:
        if not isinstance(authenticator, dict):
            names.add('未知的帳號驗證')
            continue
        if authenticator.get('enable', True) is False:
            continue
        kind = (authenticator.get('mechanism'), authenticator.get('backend'))
        if kind not in BUILTIN_AUTHN:
            raw = kind[1] if isinstance(kind[1], str) else kind[0]
            names.add(AUTHN_NAMES.get(raw) or (raw if isinstance(raw, str) and re.fullmatch(r'[a-z_]{1,32}', raw)
                                                else '未知的帳號驗證'))
    exhook = config.get('exhook')
    servers = exhook.get('servers', []) if isinstance(exhook, dict) else []
    hooks = set()
    if not isinstance(servers, list):
        hooks.add('未知的 ExHook')
    else:
        for index, server in enumerate(servers):
            if not isinstance(server, dict):
                hooks.add('未知的 ExHook')
            elif server.get('enable', True) is not False:
                hooks.add(str(server.get('name') or f'server{index + 1}')[:80])
    return {'authn': sorted(names), 'exhook': sorted(hooks)}


def credential_receivers(config):
    """Display names (kept for callers that only want to know whether there are any): [] when only built-in database
    authenticators and no ExHook remain."""
    found = credential_receiver_items(config)
    return (['外部帳號驗證（' + '、'.join(found['authn']) + '）'] if found['authn'] else []) + (
        ['ExHook'] if found['exhook'] else [])


def external_authz_items(config):
    """The enabled authorization sources that are neither a file nor the built-in database: they receive the user name and
    the topic of every publish and subscribe (D0 brings HA's sources as they are)."""
    authorization = config.get('authorization')
    sources = authorization.get('sources') if isinstance(authorization, dict) else None
    names = set()
    for source in sources if isinstance(sources, list) else []:
        if not isinstance(source, dict):
            names.add('未知的授權來源')
        elif source.get('enable', True) is not False and source.get('type') not in ('file', 'built_in_database'):
            kind = source.get('type')
            names.add(SOURCE_NAMES.get(kind) or (kind if isinstance(kind, str) and re.fullmatch(r'[a-z_]{1,32}', kind)
                                                 else '未知的授權來源'))
    return sorted(names)


def security_items(config):
    """Everything S1 names, from one effective configuration: {file_secret, jq_rule, external_authn, external_authz,
    exhook} -> [names]. Names only."""
    found = credential_receiver_items(config)
    return {'file_secret': file_secret_items(config), 'jq_rule': jq_rule_items(config),
            'external_authn': found['authn'], 'external_authz': external_authz_items(config), 'exhook': found['exhook']}


SNAPSHOT_CHANGED = ('EMQX 不能搬過來：這台 EMQX 的憑證等檔案放在資料卷裡，匯入 HA 的資料把它改掉了；為避免改變這台的連線'
                    '設定，已停止。')
ACL_REPLACED = ('HA 的權限（ACL）檔取代了這台的：{names}；匯入後裝置的存取權限以 HA 的為準（HA 預設的權限檔最後一行是「全部允許」，'
                '有帳號的裝置能讀寫幾乎所有主題）。這台原本的檔案不會寫回，匯入前的自動備份裡還有。')


def snapshot_file_digests(snapshot_path):
    """{name: sha256 hex} of the target snapshot's data-volume files except the override file (EMQX rewrites
    configs/cluster.hocon on every settings change; every other one must reach the candidate byte for byte, but for
    the ACL file HA's import writes: see check_snapshot_files)."""
    digests = {}
    with ha_odoo._live_tar(snapshot_path, '目標 EMQX 設定快照') as source:
        for member in source:
            name = ha_odoo._norm(member.name)
            if name and member.isfile() and name != 'configs/cluster.hocon':
                digest = hashlib.sha256()
                handle = source.extractfile(member)
                for chunk in iter(lambda: handle.read(habackup.CHUNK), b''):
                    digest.update(chunk)
                digests[name] = digest.hexdigest()
            source.members.clear()
    return digests


def check_snapshot_files(read_candidate, digests):
    """Every data-volume file this device's effective configuration names (its ACL, certificates, ...) is looked at in the
    finished candidate. HA's export inlines HA's file ACL and the import writes it to <data_dir>/authz/acl.conf (EMQX 5.8.9
    emqx_authz_file.erl:64-75,120-121), which IS this device's ACL once the Dashboard edited it (security review SR-2,
    2026-11-23). HAOS replaces the folder, so HA's ACL file replaces this device's (D3, E-75): the names of those that
    differ are returned for a notice and nothing is written back. Any other file (a certificate, a key) must still reach
    the candidate byte for byte: HA's import has no business changing it. Digests only; contents never leave the
    candidate. Returns the sorted names of the replaced ACL files."""
    replaced = []
    for name, want in sorted(digests.items()):
        path = f'{DATA_TARGET}/{name}'
        result = read_candidate(['sha256sum', path])
        raw = result.stdout or b''
        same = (not result.returncode and len(raw) <= 4096
                and re.fullmatch(rb'[0-9a-f]{64}  ' + re.escape(path.encode()) + rb'\n', raw) is not None
                and raw[:64].decode('ascii') == want)
        if same:
            continue
        if name.startswith('authz/'):
            replaced.append(name)
            continue
        raise BackupError('incompatible', SNAPSHOT_CHANGED)
    return replaced


def check_candidate_bootstrap(tmp, target, config, *, lost=None, etc_dir=ETC_DIR, log_dir=LOG_TARGET):
    """The candidate can read this device's bootstrap files. E-61: with `lost` (a list) one it cannot read is not refused:
    its path is appended and the caller says this device's pre-created accounts may have to be made again. The banned list's
    and the API keys' bootstrap files are found by the same resolver as every other file of a setting (resolve_path); one
    whose place cannot be told is looked at like one the candidate cannot read."""
    paths = bootstrap_references(config, target.files, target.secrets, lost=[] if lost is not None else None)
    for key in ('banned', 'api_key'):
        value = config.get(key)
        path = value.get('bootstrap_file') if isinstance(value, dict) else None
        if isinstance(path, str) and path:
            resolved = resolve_path(path, etc_dir=etc_dir, log_dir=log_dir, env=getattr(target, 'env', None))
            if resolved is None:
                if lost is None:
                    raise BackupError('incompatible', 'EMQX 候選無法讀取 bootstrap 掛載，已停止。')
                lost.append(path[:200])
                continue
            paths.add(resolved)
    for path in sorted(paths):
        checked = tmp.exec('emqx-new', ['test', '-f', path, '-a', '-r', path],
                           timeout=30, max_output=1024, check=False)
        if checked.returncode:
            if lost is None:
                raise BackupError('incompatible', 'EMQX 候選無法讀取 bootstrap 掛載，已停止。')
            lost.append(path)


def read_authn(tmp, role, *, attempts=2):
    """AUTHN_EXPR's answer as a list of authenticators. An answer that is not a list is read once more and then stops the
    app (E-81); an empty list IS an answer (nobody has to log in: HA's own choice, S2), not a failure (E-62)."""
    for _attempt in range(attempts):
        text = evaluate(tmp, role, AUTHN_EXPR)
        if re.fullmatch(r'\s*\[.*\]\s*(?:ok\s*)?', text, re.S):
            return parse_authn(text)
    raise BackupError('job-failed', '無法確認匯入後的 EMQX 帳號驗證設定，已停止。')


def partial_items(output):
    """What EMQX's `data import` said it could not import, as far as names go (E-67): the setting roots and tables its answer
    names, nothing else (its text can hold values). [] when it names none."""
    text = (output or b'').decode('utf-8', 'replace')
    return ([root for root in DATA_ROOTS if re.search(r'(?<![A-Za-z0-9_])' + root + r'(?![A-Za-z0-9_])', text)]
            + [table for table in TABLES if table in text])


def read_schedulers(execute):
    """schedulers(), or None when they cannot be read (E-57: no reason to stop)."""
    try:
        return schedulers(execute)
    except BackupError as error:
        if haissues.is_job_wide(error):
            raise
        return None


def target_broker(work, tmp, target, export, ids, *, hint='', target_snapshot=None, target_config=None,
                  image_fingerprints=None, target_boot=None, target_vm=None, readings=None, notes=None):
    """This device's broker on an empty volume: import HA's export, make HA's authentication and authorization HA's, load
    this device's other settings back, verify.

    `target_boot`: this device's configuration in its boot form (boot_form); the candidate, just booted from the
    snapshot, must equal it (a root that does not is said, E-60: `notes['differs']`, and the candidate's own value
    becomes the baseline: what this device would have after its next start). Without it the plain raw configuration must
    be equal (callers that read no boot form).
    `target_vm`: this device's (total, online) schedulers (schedulers); the candidate starts with them (E-57: that it
    answers something else is only logged).
    `readings`: HA's broker's (ha_broker): HA's authenticators, authorization sources, no-match rule. Without them the
    old internal path (this device's no-match rule kept) runs.
    `notes` (a dict) gets what the caller says to the customer: access_env, differs, partial (E-67), acl_replaced (D3),
    lost (E-48, E-49, E-61), bootstrap (E-68, E-69), anonymous, device_authenticated, ticker, security (S1: names only)."""
    notes = {} if notes is None else notes
    name = os.path.basename(export)
    snapshot_digests = snapshot_file_digests(target_snapshot) if target_snapshot is not None else None
    tmp.volume('emqx-in')
    tmp.volume_import('emqx-in', lambda out: _folder_tar(out, 'in', ids[0], ids[1], [(name, export)]))
    tmp.volume('emqx-new')
    if target_snapshot is not None:
        import_target_snapshot(tmp, target_snapshot, ids)
    tmp.volume('emqx-new-log')
    # The product's Target adds its EnvironmentFile= files, which podman reads itself (their values never reach a
    # command line, SR-8); internal callers' target objects carry their env as given.
    env, env_files = target.candidate_env() if isinstance(target, Target) else (target.env, [])
    if isinstance(target, Target):
        notes['access_env'] = list(target.access_env)
        for path in target.skipped_env:
            work.log(f'這台 EMQX 的 EnvironmentFile（{path}）不在擁有者的家目錄下或讀不到，暫用的 EMQX 沒有用它；設定的差異會列出。')
    if target_vm is not None:   # Target.env holds EMQX_* settings only: this is the candidate's one Erlang flag
        env = dict(env, ERL_AFLAGS=f'+S {target_vm[0]}:{target_vm[1]}')   # --env wins over an env file's value
    # E-23, E-35: a folder this device writes its logs or crash dump to besides /opt/emqx/log gets the candidate's own log volume
    # (scratch: logs are not carried); this device's real folder, when it is one of its mounts, is not mounted for the candidate.
    scratch = [(tmp.name('emqx-new-log'), folder, None) for folder in notes.get('scratch') or ()]
    mounts = [item for item in target.files if item[1] not in set(notes.get('scratch_drop') or ())]
    tmp.run('emqx-new', target.image, [], detach=True, read_only_root=True, env=env, env_files=env_files,
            secrets=target.secrets,
            volumes=[(tmp.name('emqx-new'), DATA_TARGET, None), (tmp.name('emqx-new-log'), LOG_TARGET, None),
                     (tmp.name('emqx-in'), WORK, None)] + scratch + mounts)
    wait_ready(tmp, 'emqx-new', checkpoint=work.checkpoint)
    ticker_pid = quiesce_system_ticker(tmp, 'emqx-new')
    read_candidate = lambda command: tmp.exec('emqx-new', command, timeout=120,
                                               max_output=MAX_HOCON, check=False)
    if target_vm is not None and read_schedulers(read_candidate) != target_vm:
        work.log('暫用的 EMQX 的執行環境（排程器數量）和這台不同；不影響資料，設定的差異會列出。')
    if image_fingerprints is not None and tls_fingerprints(read_candidate, image_fingerprints) != image_fingerprints:
        raise BackupError('incompatible', 'EMQX 候選憑證與目標不一致，已停止。')
    if target_config is not None:
        if target_etc_dir(read_candidate) != notes.get('etc_dir', ETC_DIR):   # E-24: this device's own etc directory
            raise BackupError('incompatible', 'EMQX 候選啟動後設定與目標不一致，已停止。')
        want = target_boot if target_boot is not None else target_config
        got = boot_form(read_candidate) if target_boot is not None else read_effective_config(read_candidate)
        differ = sorted(root for root in set(want) | set(got) if want.get(root) != got.get(root))
        if differ:
            # E-60: this device's running settings are not what its files give at a start (a setting changed and not yet
            # restarted, a source it did not know). Only another node name is dangerous (the database would not open); the
            # rest is listed (root names only, schema keys, never values) and what the candidate booted with is what this
            # device will have after its next start: the baseline of every later comparison (E-74, E-90).
            wanted_node, got_node = want.get('node'), got.get('node')
            if (wanted_node != got_node and not (isinstance(wanted_node, dict) and isinstance(got_node, dict)
                                                 and wanted_node.get('name') == got_node.get('name'))):
                raise BackupError('incompatible', 'EMQX 候選啟動後的節點名稱和這台不同，已停止。')
            notes['differs'] = [root for root in differ if root not in DATA_ROOTS]   # HA's roots replace this device's anyway
            raw_now = read_effective_config(read_candidate)
            target_config = dict(target_config)
            target_boot = dict(target_boot) if target_boot is not None else None
            for root in differ:
                for baseline, source in ((target_config, raw_now), (target_boot, got)):
                    if baseline is None:
                        continue
                    if root in source:
                        baseline[root] = source[root]
                    else:
                        baseline.pop(root, None)
        check_candidate_bootstrap(tmp, target, target_config, lost=notes.setdefault('lost', []),   # E-61
                                  etc_dir=notes.get('etc_dir', ETC_DIR), log_dir=notes.get('log_dir', LOG_TARGET))
    seeded = parse_counts(evaluate(tmp, 'emqx-new', COUNT_EXPR))
    strict = parse_strict(evaluate(tmp, 'emqx-new', STRICT_EXPR))
    authn = read_authn(tmp, 'emqx-new')
    if strict is None or len(seeded) != len(TABLES):   # E-62: a device without any authenticator is no failure
        raise BackupError('job-failed', '無法讀取這台 EMQX 的設定。')
    check_export(lambda command: tmp.exec('emqx-new', command, timeout=1800, max_output=MAX_HOCON, check=False), name,
                 hint=hint)
    notes['ticker'] = assert_system_ticker(tmp, 'emqx-new', ticker_pid)
    work.log('把 HA 的 EMQX 資料匯入暫用的 EMQX（這台的映像與設定）')
    out = ctl(tmp, 'emqx-new', ['data', 'import', f'{WORK}/in/{name}'], timeout=1800).stdout or b''
    notes['partial'] = [] if b'imported successfully' in out else (partial_items(out) or [''])   # E-67
    if target_config is not None:
        observe = getattr(work, '_emqx_build_stage', None)
        facts = {'bootstrap': []}
        if readings is not None:
            facts = apply_ha_access(tmp, read_candidate, readings, target_config, list(notes.get('lost') or ()),
                                    observe=observe)
        notes['bootstrap'] = facts['bootstrap']
        restore_target_settings(tmp, target_config, read_candidate, observe=observe, original_boot=target_boot)
        if image_fingerprints is not None and tls_fingerprints(read_candidate, image_fingerprints) != image_fingerprints:
            raise BackupError('incompatible', 'EMQX 匯入後憑證與目標不一致，已停止。')
        if snapshot_digests:   # after every settings change; the remaining checks only read
            notes['acl_replaced'] = check_snapshot_files(read_candidate, snapshot_digests)
        final = read_effective_config(read_candidate)
        notes['security'] = security_items(final)
        # E-41, E-42, E-43, E-44, E-47: what this device had of its own (its boot form: both sides have their defaults filled)
        # and what the import did with it
        notes['device_items'] = ha_emqx_settings.own_items(target_boot if target_boot is not None else target_config, final)
        check_candidate_bootstrap(tmp, target, final, lost=notes.setdefault('lost', []),
                                  etc_dir=notes.get('etc_dir', ETC_DIR), log_dir=notes.get('log_dir', LOG_TARGET))
    else:
        # Legacy internal test path only; public convert remains blocked.
        snippet = f'authorization {{\n  no_match = {strict[0]}\n  deny_action = {strict[1]}\n  sources = []\n}}\n'.encode()
        tmp.exec('emqx-new', ['sh', '-c', f'umask 077; cat > {WORK}/in/strict.hocon'], input=snippet,
                 timeout=120, max_output=64 * 1024)
        ctl(tmp, 'emqx-new', ['conf', 'load', '--merge', f'{WORK}/in/strict.hocon'], timeout=600)
    after = parse_strict(evaluate(tmp, 'emqx-new', STRICT_EXPR))
    want_strict = tuple(readings['strict']) if readings is not None and readings.get('strict') else strict
    if after != want_strict:   # E-80: right after applying, the rule really is HA's
        raise BackupError('job-failed', '無法確認匯入後的 EMQX 存取政策（未符合規則的主題的處理）和 HA 的相同，已停止。')
    after_authn = read_authn(tmp, 'emqx-new')
    notes['anonymous'] = not any(a['enable'] for a in after_authn)   # E-82 (S2): HA's own choice, restored as it is
    notes['device_authenticated'] = any(a['enable'] for a in authn)
    counts = parse_counts(evaluate(tmp, 'emqx-new', COUNT_EXPR))
    notes['ticker'] = notes['ticker'] and assert_system_ticker(tmp, 'emqx-new', ticker_pid)
    return seeded, counts, strict, authn


SYS_SLACK = 64   # retained messages: rows the broker's own $SYS topics may add or leave while its ticker runs (E-13)


MARKER = 'woow-ha-import.json'
MARKER_BODY = '{"kind":"woow-ha-import","version":1,"app":"emqx"}\n'


def write_marker(tmp):
    """DESIGN H-2: a file in the candidate's data volume that says this broker's access settings are HA's. The package's own
    checks (tests/smoke.sh A4 the Dashboard login with its generated password, A5 no anonymous login, A6 its own MQTT
    user, A10 no subscription to another user's topics) are about the settings the package installed; after an import
    HA's authentication, authorization, ACL file and Dashboard accounts are in force (D0-D3, D5), and without this
    marker every `upgrade.sh` of the package would fail its smoke test and roll the upgrade back. A fixed text, no value of
    this device or of HA; it travels with the data volume and goes with it when an older backup is restored."""
    result = tmp.exec('emqx-new', ['sh', '-c', f"umask 077; printf '%s' '{MARKER_BODY.strip()}' > {DATA_TARGET}/{MARKER}"],
                      timeout=60, max_output=4096, check=False)
    if result.returncode:
        raise BackupError('job-failed', '無法在暫用的 EMQX 資料卷留下匯入標記，已停止；這台沒有任何改變。')


def check_counts(ha, seeded, counts, *, observe=None, loose=()):
    """Tables where the import lost or invented rows (HA's rows must all be there, at most plus the seed). `loose`: the
    tables whose count may also differ by up to SYS_SLACK rows because a broker's system-message ticker could not be paused
    (E-13; only the retained messages, never an account, a rule or a key)."""
    problems = []
    for table in TABLES:
        mine, theirs, seed = counts.get(table, -1), ha.get(table, -1), max(seeded.get(table, 0), 0)
        if theirs < 0:
            continue
        slack = SYS_SLACK if table == 'emqx_retainer_message' and table in loose else 0
        if not theirs <= mine <= theirs + seed + slack:
            if observe is not None:
                observe(table, 'underflow' if mine < theirs else 'overflow')
            problems.append(f'{table}（HA {theirs}，匯入後 {mine}）')
    return problems


def data_volume(src_path, out):
    """woow_emqx_data from the broker's volume export without generated configs, cluster.hocon backups, exports and
    traces."""
    return hacommon.copy_live(src_path, out, drop=lambda name: DROPPED.fullmatch(name) is not None,
                              what='暫用 EMQX 的資料卷')


# ====================================================================== readback after the restore

READBACK_KIND = 'emqx-readback'
READBACK_VERSION = 1
# The tables only an administrator changes (clients, expiry and the broker itself move the retained messages and the
# banned list at any time; those are counted by the conversion, never compared after the restore).
STABLE_TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_admin', 'emqx_app', 'emqx_psk',
                 'emqx_banned_rules')
# Fixed expression, one read-locked transaction per table: the row count and the SHA-256 of the sorted SHA-256s of the
# rows' external terms (order independent). A table this broker does not have answers -1. Values never leave it.
TABLES_RECEIPT_EXPR = ' '.join(('''
try
 <<"5.8.9">> = iolist_to_binary(emqx_release:version()),
 One = fun(T) ->
   case catch mnesia:table_info(T, size) of
     N0 when is_integer(N0) ->
       {atomic, {N, H}} = mnesia:transaction(fun() ->
           ok = mnesia:read_lock_table(T),
           {K, Hs} = mnesia:foldl(fun(Row, {C, Acc}) -> {C + 1, [crypto:hash(sha256, term_to_binary(Row)) | Acc]} end,
                                  {0, []}, T),
           K = mnesia:table_info(T, size),
           {K, crypto:hash(sha256, term_to_binary(lists:sort(Hs)))}
         end),
       io_lib:format("~s:~B:~s;", [T, N, binary:encode_hex(H)]);
     _ -> io_lib:format("~s:-1:-;", [T])
   end
 end,
 io:format("WOOWTAB:~s:END", [lists:flatten([One(T) || T <- [''' + ', '.join(STABLE_TABLES) + ''']])])
catch _:_ -> io:put_chars("WOOWTAB:REFUSED") end.
''').split())
RECEIPT_RE = re.compile(rb'WOOWTAB:((?:[a-z_]{1,64}:(?:-1:-|[0-9]{1,10}:[0-9A-F]{64});){1,32}):END(?:ok)?')


def table_receipts(execute):
    """{table: [rows, sha256 hex lowercase | None]} of STABLE_TABLES, from one fixed `emqx eval`."""
    result = execute(['emqx', 'eval', TABLES_RECEIPT_EXPR])
    raw = (result.stdout or b'').strip()
    match = RECEIPT_RE.fullmatch(raw) if result.returncode == 0 and len(raw) <= 16384 else None
    if match is None:
        raise BackupError('job-failed', '無法讀取 EMQX 內建資料庫的核對資料，已停止。')
    found = {}
    for item in match[1].decode('ascii').split(';')[:-1]:
        name, rows, digest = item.split(':')
        found[name] = [int(rows), None if digest == '-' else digest.lower()]
    if set(found) != set(STABLE_TABLES):
        raise BackupError('job-failed', '無法讀取 EMQX 內建資料庫的核對資料，已停止。')
    return found


# Security review SR-4 (2026-11-23): the RAW configuration also holds this device's own secrets that a converted
# backup does not otherwise carry (dashboard.default_password and node.cookie come from the environment, a 5.8.9 broker
# answers them in emqx:get_raw_config/1). The readback travels in the converted backup, so before hashing every value
# under a secret-named key, every HTTP header value and the user part of a URL become one fixed marker (both sides:
# the conversion and verify_restored); a changed secret is then not compared, every other value still is.
SECRET_WORDS = ('password', 'passwd', 'secret', 'cookie', 'token', 'key')
REDACTED = '<redacted>'
URL_USER_RE = re.compile(r'(?<=//)[^/@\s]+@')


def _secret_name(name):
    return isinstance(name, str) and any(word in name.lower() for word in SECRET_WORDS)


def redacted(value, secret=False, everything=False):
    """`value` with its secret leaves replaced by REDACTED: a scalar under a secret-named key (also inside a list
    there), every scalar below a `headers` key, the user part of `scheme://user[:password]@host`. Containers stay; below
    a secret-named key a map's own keys decide again (e.g. password_hash_algorithm.name is still compared)."""
    if isinstance(value, dict):
        return {key: redacted(item, everything or _secret_name(key), everything or key == 'headers')
                for key, item in value.items()}
    if isinstance(value, list):
        return [redacted(item, secret, everything) for item in value]
    if secret or everything:
        return REDACTED
    if isinstance(value, str) and '@' in value:
        return URL_USER_RE.sub(REDACTED + '@', value)
    return value


def config_roots(config):
    """{root: sha256 hex} of an effective RAW configuration (canonical JSON per root: key order never matters, list
    order does), secrets redacted first (SR-4). Derived from what the backup itself holds; never logged."""
    return {root: hashlib.sha256(json.dumps(redacted(value), sort_keys=True, ensure_ascii=True,
                                            separators=(',', ':')).encode('ascii')).hexdigest()
            for root, value in config.items()}


def readback_record(config, tables):
    """The record of a readback. `tables` None (E-84: the receipt could not be read) is written in the one form the backup's
    schema knows for "no such table" for every table -- [-1, None] -- which a comparison reads as "not recorded"."""
    if tables is None:
        tables = {table: [-1, None] for table in STABLE_TABLES}
    return {'kind': READBACK_KIND, 'version': READBACK_VERSION, 'config_roots': config_roots(config), 'tables': tables}


def tables_recorded(record):
    """False for a record whose tables were not read (E-84: every table [-1, None]); a real 5.8.9 broker has them all."""
    tables = (record or {}).get('tables')
    return not (isinstance(tables, dict) and tables and all(value == [-1, None] for value in tables.values()))


def receipts_or_none(execute):
    """table_receipts(), or None when the receipt cannot be read (E-84); a job-wide error still ends the job."""
    try:
        return table_receipts(execute)
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return None


def candidate_readback(tmp, *, notes=None):
    """(readback record) of the finished candidate: read after this device's settings came back and its rows were counted.
    E-84: when the receipt of the administrator tables cannot be read, the record says so (`tables` None, a notice in
    `notes`) and the restore skips that comparison: the rows were counted in the conversion (E-83)."""
    read = lambda command: tmp.exec('emqx-new', command, timeout=120, max_output=MAX_HOCON, check=False)
    # The restored broker reads these settings at its boot: the record holds their boot form (boot_form).
    tables = receipts_or_none(read)
    if tables is None and notes is not None:
        notes['receipt_unreadable'] = True
    return readback_record(boot_form(read), tables)


def compare_readback(expected, actual):
    """What differs between two readback records, as names only (roots, tables); [] when equal."""
    problems = []
    want, have = expected.get('config_roots') or {}, actual.get('config_roots') or {}
    roots = sorted(name for name in set(want) | set(have) if want.get(name) != have.get(name))
    if roots:
        problems.append(f'設定（{hacommon.names(roots, 8)}）')
    want, have = expected.get('tables') or {}, actual.get('tables') or {}
    tables = [] if not (tables_recorded(expected) and tables_recorded(actual)) else sorted(
        name for name in set(want) | set(have) if want.get(name) != have.get(name))
    if tables:
        problems.append(f'內建資料庫（{hacommon.names(tables, 8)}）')
    return problems


def compare_parts(expected, actual):
    """(settings, tables): what differs between two readback records, each as the sentence compare_readback gives, [] when
    equal. E-90: only a difference in the tables (accounts, ACL rules, keys) fails a restore; one in the settings alone is
    reminded."""
    texts = compare_readback(expected, actual)
    return [t for t in texts if t.startswith('設定')], [t for t in texts if t.startswith('內建資料庫')]


def wait_live_ready(execute, *, sleep=time.sleep, clock=time.monotonic, timeout=READY_TIMEOUT, size=None, running=None,
                    extend=READY_EXTENDED):
    """Wait until the restored broker answers `emqx ctl status`. E-88: the wait grows with the data (`size`: bytes) and, while
    the container still runs after it (`running`: a callable, True while the container is up), goes on for `extend` seconds
    more: a slow start is no failure. A container that really ended (or never answers after all that) raises, and the
    restore then rolls back by itself."""
    limit = podman.scaled_timeout(timeout, size)
    deadline = clock() + limit
    extended = False
    while True:
        try:
            result = execute(['emqx', 'ctl', 'status'])
            if result.returncode == 0 and b'is started' in (result.stdout or b''):
                return
        except BackupError:
            pass   # a timed-out probe is "not ready yet"; the deadline still holds
        if running is not None and not running():
            raise BackupError('job-failed', '還原後的 EMQX 啟動後又結束了，已停止。')
        if clock() >= deadline:
            if extended or running is None or not extend:
                raise BackupError('job-failed', f'還原後的 EMQX 在 {limit + (extend if extended else 0)} 秒內沒有啟動完成，已停止。')
            extended = True   # it still runs: only slow
            deadline = clock() + extend
        sleep(2)


def verify_restored(adapter, app, check, *, log, sleep=time.sleep, clock=time.monotonic):
    """After a restore of a converted backup started the units: the restored broker must hold the administrator tables the
    conversion verified (MQTT accounts, ACL rules, keys, ...: a difference raises BackupError and the restore rolls back by
    itself). E-90: a difference in the settings alone (a setting changed after the conversion, the CPU count) is only
    reminded in the log, no rollback. E-89: a record this engine does not know is skipped with a reminder (the restore's
    preflight has refused a backup that needs a newer engine: haimport.import_check_problem), the restored data is not
    undone for it. E-84: a table receipt that cannot be read (here or in the record) is skipped with a reminder."""
    if (not isinstance(check, dict) or check.get('kind') != READBACK_KIND
            or check.get('version') != READBACK_VERSION):
        log('這份備份的 EMQX 核對資料格式這版備份元件不認得，已略過還原後的核對（資料已經還原好，沒有回復）；請更新備份元件。')
        return
    quadlets = adapter.read_quadlets()
    shim = type('LiveWork', (), {'quadlets': lambda self, _app: quadlets, 'runner': lambda self, _app: adapter.runner})()
    target = Target(shim, app)

    def execute(command):
        return adapter.runner.podman('exec', target.container, *command, timeout=120, max_output=MAX_HOCON,
                                     check=False)

    def running():
        result = adapter.runner.podman('container', 'inspect', '--format', '{{.State.Running}}', target.container,
                                       timeout=60, max_output=1024, check=False)
        return result.returncode == 0 and (result.stdout or b'').strip() == b'true'
    wait_live_ready(execute, sleep=sleep, clock=clock, running=running)
    tables = receipts_or_none(execute)
    actual = readback_record(boot_form(execute), tables)
    settings, rows = compare_parts(check, actual)
    if rows:
        raise BackupError('job-failed', f'EMQX 還原後的{"、".join(rows)}和轉換時核對的不同，已停止；'
                                        '通常是轉換之後有人在這台 EMQX 改過帳號、規則或金鑰，請重新檢查與轉換後再還原。', app=app.id)
    if tables is None or not tables_recorded(check):
        log('EMQX 還原後讀不到（或備份沒有記錄）內建資料庫的核對值，已略過帳號與 ACL 規則的核對；筆數在轉換時已核對過。')
    if settings:
        log(f'提醒：EMQX 還原後的{"、".join(settings)}和轉換時核對的不同（通常是轉換之後這台 EMQX 的設定改過，或 CPU 數不同）；'
            '帳號、ACL 規則和金鑰都相同，所以沒有回復。')
    elif tables is not None and tables_recorded(check):
        log('EMQX 還原後核對一致：設定（含授權來源、ACL 檔案路徑、節點與叢集）和內建資料庫的帳號與 ACL 規則都和轉換時相同')


# ====================================================================== analysis

# ---------------------------------------------------------------------- MQTT password hashing (SR-5)
# D0 / SR-5: HA's `authentication` root replaces this device's (DATA_ROOTS) and EMQX checks every stored row of the built-in
# password database with the authenticator's CURRENT hashing; it never re-hashes a stored row (emqx_authn_mnesia.erl:130-131
# update = create, :137-161 authenticate; the bootstrap import never overwrites a row, :556-565 override => false). So when
# HA hashes differently this device's own MQTT accounts no longer log in with their passwords: the check names them (a
# notice) and the conversion repeats it. D1 (owner decision 2026-11-25, HAOS parity): HA's `plain` stores every password as it
# is (emqx_passwd.erl:104 hash_data(plain, P) = P, with an empty salt: emqx_authn_password_hashing.erl:206-207); HAOS restores
# such rows as they are, so they are no longer refused: they are named in a notice, and the text says the clear-text password
# stays on this device and in every later backup.
RESET_HOW = ('到這台 EMQX 管理頁「存取控制 → 認證」的內建資料庫替這些帳號重設密碼或重新建立；由這台 bootstrap 帳號檔建立的帳號，'
             '刪除後重新啟動 EMQX 就會用原本的密碼建回。')
ACCOUNTS_STOP = ('HA 的 EMQX 保存 MQTT 密碼的方式（{ha}）和這台（{mine}）不同，匯入後以 HA 的為準：這台現有的 MQTT 帳號'
                 '（{names}）匯入後無法再用原本的密碼登入，要在匯入後重新設定：' + RESET_HOW)
HASH_UNREADABLE = '無法讀取{side} EMQX 帳號驗證設定（MQTT 密碼的雜湊方式），已停止。'
PLAIN_PASSWORDS = ('HA 的 EMQX 用「plain」（不加密）的方式保存 MQTT 帳號的密碼；會照 HA 原樣匯入，明文密碼會留在這台的資料卷、轉換出的'
                   '備份和之後每一份備份裡，這台之後新增的 MQTT 帳號也會用明文保存。裝置照常登入。若要避免，請先在 HA 的 EMQX 管理頁'
                   '「存取控制 → 認證」把密碼雜湊方式改成 plain 以外的方式並重設密碼，再重新備份。')
# Security re-review 2026-11-24 (iteration 7, PLAIN_EXPR): `plain` also happens in the built-in password database of an MQTT
# listener or a gateway, and rows HA's EMQX still keeps in clear text (written under `plain` before HA changed the algorithm
# and never set again).
PLAIN_ELSEWHERE = ('HA 的 EMQX 在 MQTT 監聽器或閘道（gateway）的內建資料庫認證用「plain」（不加密）的方式保存 MQTT 帳號的密碼；'
                   '會照 HA 原樣匯入，這些帳號的明文密碼會留在這台的資料卷和之後每一份備份裡（監聽器的認證設定不會搬，那些帳號在這台沒人用）。')
# Iteration 8: every row whose stored value is not in the form of its authenticator's hashing (PLAIN_EXPR), not only
# empty-salt rows that are neither hex nor start with `$2`; `{names}` = user ids, a listener's or gateway's own chain in
# brackets.
CLEAR_ROWS = ('HA 的 EMQX 內建資料庫裡有 {count} 個 MQTT 帳號的密碼沒有以所屬認證目前的雜湊方式保存，可能是明文（例如在改用其他雜湊方式之前'
              '用「plain」設定，或以「hash」方式匯入帳號時填入了沒有雜湊的密碼；括號裡是不屬於全域認證的帳號所在的監聽器或閘道）；'
              '這些帳號在 HA 現在也無法用密碼登入，會照 HA 原樣匯入。真的是明文時，明文密碼會留在這台的資料卷和之後每一份備份裡。'
              '可以略過它們：在 HA 重設這些帳號的密碼或刪除不用的帳號，再重新備份。')
HASH_NOT_READ = ('讀不出 HA 的 EMQX 的 MQTT 密碼保存方式，無法事先知道有沒有明文密碼；照 HA 原樣匯入，真有明文密碼時它會留在這台和之後每一份'
                 '備份裡。')
# Iteration 8 (O-3): HA's built-in password database is disabled or absent. HA's `authentication` root replaces this
# device's, so this device's MQTT accounts no longer log in with their passwords.
DB_OFF = ('HA 的 EMQX 沒有啟用內建資料庫的帳號密碼認證，匯入後以 HA 的為準：這台的 MQTT 帳號（{names}）匯入後無法再用帳號密碼'
          '登入。要繼續使用這些帳號，請先在 HA 的 EMQX 管理頁「存取控制 → 認證」啟用內建資料庫認證，再重新製作 HA 備份。')
ACCOUNTS_UNKNOWN = ('讀不出這台 EMQX 的 MQTT 帳號和密碼保存方式，沒辦法事先列出匯入後會失效的帳號（功能不受影響）；匯入後這台原本的 MQTT '
                    '帳號可能要重設密碼：' + RESET_HOW)
# pbkdf2 without `dk_length` derives the MAC's own length (emqx_passwd.erl:140-141, 153-158).
PBKDF2_DK = {'sha': 20, 'sha224': 28, 'sha256': 32, 'sha384': 48, 'sha512': 64}
SALT_TEXT = {'prefix': '，鹽在前', 'suffix': '，鹽在後', 'disable': '，不加鹽'}


def plain_notices(readings):
    """D1 (E-16..E-19): [(issue id, message, names)] for how HA's EMQX stores MQTT passwords; every one is a notice, nothing is
    refused. Names only: the accounts (first ten, `counted`), never a password or a hash."""
    readings = readings or {}
    found = []
    if readings.get('hash_unreadable'):
        return [('emqx.hashing-unreadable', HASH_NOT_READ, [])]
    hashing = readings.get('hashing')
    if hashing is not None and hashing['name'] == 'plain':
        found.append(('emqx.plain-passwords', PLAIN_PASSWORDS, []))
    plain = readings.get('plain') or {}
    if plain.get('elsewhere'):
        found.append(('emqx.plain-elsewhere', PLAIN_ELSEWHERE, []))
    if plain.get('clear'):
        shown = [user if group == GLOBAL_GROUP else f'{user[:40]}（{group[:18]}）' for user, group in plain['names']]
        found.append(('emqx.clear-rows', CLEAR_ROWS.format(count=plain['clear']), shown))
    return found


GLOBAL_GROUP = 'mqtt:global'


def counted(names, count):
    """The first ten names (hacommon.names: control and format characters shown as `?`), then 「等 N 個」 for `count`."""
    text = hacommon.names(list(names)[:10], 10)
    return text + (f' 等 {count} 個' if count > 10 else '')


def rows_still_verify(mine, theirs):
    """Whether a row this device's built-in password database wrote with its hashing `mine` is still accepted when HA's
    hashing `theirs` checks it (emqx_authn_password_hashing.erl:252-269 check_password, emqx_passwd.erl:67-104)."""
    if 'bcrypt' in (mine['name'], theirs['name']):
        return mine['name'] == theirs['name']   # bcrypt reads the rounds and the salt from the stored hash (:252-253)
    if 'pbkdf2' in (mine['name'], theirs['name']):
        def params(hashing):
            return (hashing['name'], hashing['mac_fun'], hashing['iterations'],
                    hashing['dk_length'] or PBKDF2_DK.get(hashing['mac_fun']))
        return params(mine) == params(theirs)
    # plain, md5, sha, sha256, sha512: the same function and salt position. A row written with `disable` has an empty
    # salt (emqx_authn_password_hashing.erl:237-243), and an empty salt before or after the password hashes the password
    # alone (emqx_passwd.erl:92-97), so it is accepted whatever position HA uses.
    return mine['name'] == theirs['name'] and (mine['salt'] == theirs['salt'] or mine['salt'] == 'disable')


def hashing_text(hashing):
    """A short description of one hashing (the parser's tokens only: lowercase letters, digits, `_`, numbers)."""
    if hashing['name'] == 'pbkdf2':
        length = f'，{hashing["dk_length"]} 位元組' if hashing['dk_length'] else ''
        return f'pbkdf2（{hashing["mac_fun"]}，{hashing["iterations"]} 次{length}）'
    if hashing['name'] == 'bcrypt':
        return 'bcrypt'
    return hashing['name'] + SALT_TEXT.get(hashing['salt'], '')


def device_execute(work, app, target):
    """A read on this device's running broker as the owner (podman exec of a fixed command; nothing is changed)."""
    def execute(command):
        return work.runner(app).podman('exec', target.container, *command, timeout=120, max_output=MAX_HOCON,
                                      check=False)
    return execute


def device_accounts(execute):
    """This device's built-in password database, read-only from its running broker: None when it has no such
    authenticator, else {'hashing', 'count', 'names'} (user ids only, the first ten: USERS_EXPR reads the table's keys,
    never a password hash or salt). An answer that cannot be read refuses (SR-5: never guessed)."""
    def answer(expression):
        result = execute(['emqx', 'eval', expression])
        if result.returncode:
            raise ValueError('eval failed')
        return (result.stdout or b'').decode('utf-8', 'replace')
    try:
        hashing = parse_hashing(answer(HASH_EXPR))
        if hashing is None:
            return None
        count, names = parse_users(answer(USERS_EXPR))
    except ValueError:
        raise BackupError('incompatible', HASH_UNREADABLE.format(side='這台')) from None
    return {'hashing': hashing, 'count': count, 'names': names}


def hash_change(ha_hashing, device):
    """None when the import leaves this device's MQTT accounts able to log in, else {'ha', 'mine', 'names'} for the
    texts: HA has a built-in password database whose hashing no longer accepts the rows of this device's, and this device
    has users there (`names`: through hacommon.names, control characters shown as `?`)."""
    if ha_hashing is None or device is None or device['count'] <= 0:
        return None
    if rows_still_verify(device['hashing'], ha_hashing):
        return None
    return {'ha': hashing_text(ha_hashing), 'mine': hashing_text(device['hashing']),
            'names': counted(device['names'], device['count'])}


def database_off(readings, device):
    """DB_OFF's text when HA's built-in password database is disabled or absent and this device has MQTT accounts in
    its own (O-3, E-68), else None."""
    if readings is None or device is None or device['count'] <= 0:
        return None
    hashing = readings.get('hashing')
    if hashing is not None and hashing['enable']:
        return None
    return DB_OFF.format(names=counted(device['names'], device['count']))


def section(src, node, readings, *, version, profile=None):
    counts = (readings or {}).get('counts') or {}

    def rows(*tables):
        return sum(max(counts.get(t, 0), 0) for t in tables)

    # `target_authorization` stays an (empty) key for the page: HA's authorization replaces this device's (D0), so what
    # this device has is no longer what the import is judged by.
    return {'emqx_version': VERSIONS.upstream(src.addon.version) if src.addon else '', 'target_version': version or '',
            'node_name': node or '', 'files': src.files, 'bytes': src.bytes,
            'mqtt_users': rows('emqx_authn_mnesia', 'emqx_authn_scram_mnesia'), 'acl_rules': rows('emqx_acl'),
            'dashboard_users': rows('emqx_admin'), 'api_keys': rows('emqx_app'),
            'banned': rows('emqx_banned', 'emqx_banned_rules'), 'psk': rows('emqx_psk'),
            'retained_messages': rows('emqx_retainer_message'),
            'default_dashboard_password': bool((readings or {}).get('default_admin')),
            'anonymous': readings is not None and not any(a['enable'] for a in readings['authn']),
            'hot_backup': bool(hint_for(src.addon)), 'plugins': sorted(src.plugins),
            'ha_hosts': hacommon.ha_hosts(src.hocon)[:20], 'target_authorization': list(profile or ())}


# ====================================================================== the job steps

VERSION_EXPR = 'io:format("WOOWVER:~s:END", [emqx_release:version()]).'


def _prepare(work, app):
    """This device's EMQX (Target) and its version from the image's label (None when the image has none: E-04). The image
    itself is downloaded as the owner when it is not here (E-02, CM-05: hacommon.image_labels, hatarget.ensure_image)."""
    target = Target(work, app)
    reader = getattr(work, 'image_version', None)
    if reader is not None:
        return target, reader(app, target.image)
    return target, hacommon.semver(hacommon.image_labels(work, app, target.image).get('org.opencontainers.image.version'))


def asked_version(work, app, target):
    """E-04: the EMQX version this device's RUNNING broker names (its image carries no version label), None when it does
    not say."""
    try:
        result = work.runner(app).podman('exec', target.container, 'emqx', 'eval', VERSION_EXPR, timeout=120,
                                         max_output=4096, check=False)
    except BackupError as error:
        if haissues.is_job_wide(error):
            raise
        return None
    match = re.search(rb'WOOWVER:([0-9]+\.[0-9]+\.[0-9]+):END', result.stdout or b'')
    return hacommon.semver(match.group(1).decode('ascii')) if result.returncode == 0 and match else None


def version_lines(sink, work, app, target, version):
    """The versions' part of the app's issues (CM-01, CM-02, CM-06: a version only informs; E-03, E-04); returns the version
    to use (an image without a label is asked of the running broker)."""
    if version is None:
        asked = asked_version(work, app, target)
        if asked:
            version = asked
            sink.auto('emqx.version-asked', f'這台 EMQX 的映像沒有版本標籤，改問執行中的 EMQX：{asked}。', [asked])
    sink.extend(VERSIONS.issues(work.addon_info(SLUG).version, version))
    return version


def read_device(work, app, target):
    """(this device's built-in password database, unreadable): E-52, SR-5: read-only from its running broker; one that cannot
    be read is no reason to stop (the notice says so)."""
    try:
        return device_accounts(device_execute(work, app, target)), False
    except BackupError as error:
        if haissues.is_job_wide(error):
            raise
        return None, True


def member_pass(work, tmp):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    holder = {}

    def produce(out):
        tar = tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT, encoding=habackup.ENCODING,
                           errors=habackup.ERRORS)
        sink = _Sink(tar, work.guard)
        sink.add_member(hacommon.info('.', 'dir', mode=0o755, uid=0, gid=0, mtime=time.time()))
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, sink, checkpoint=work.checkpoint)
        tar.close()

    tmp.volume('emqx-src')
    tmp.volume_import('emqx-src', produce)
    for note in report.warnings():
        work.log(note)
    return holder['src']


class _Sink:
    """FileTar's interface over a stream tar (the throwaway volume's import)."""

    def __init__(self, tar, guard):
        self.tar, self.guard, self.names = tar, guard, set()

    def add_member(self, info, fileobj=None):
        if info.name in self.names:
            raise BackupError('corrupt-archive', 'HA 備份中有重複的項目。', member=info.name[:200])
        self.names.add(info.name)
        self.tar.addfile(info, fileobj)
        if self.guard is not None and info.isfile():
            self.guard.wrote(info.size)

    def add_entry(self, name, entry, *, mode, uid, gid):
        self.add_member(hacommon.info(name, 'file', mode=mode, uid=uid, gid=gid, mtime=entry.mtime, size=entry.size),
                        hacommon._Exact(entry))


def _clean(tmp, *roles, volumes=()):
    for role in roles:
        tmp.remove(role)
    for role in volumes:
        tmp.remove_volume(role)


# ---------------------------------------------------------------------- what the customer is told (haissues)

ACCESS_FROM_HA = ('EMQX 的帳號驗證、授權來源（含 ACL 檔案）和「沒有符合規則的主題時{rule}」的處理，匯入後都以 HA 的為準（HAOS 還原也是這樣）；'
                  '這台的位址、連接埠、節點名稱和其他設定不變。')
DASHBOARD_DEFAULT = 'HA 的 EMQX Dashboard 仍用預設帳號密碼（admin／public），會照 HA 原樣搬過來，匯入後這台的 Dashboard 也用這組帳密。'
DASHBOARD_EXPOSED = (DASHBOARD_DEFAULT + '這台的 Dashboard 目前{where}，任何連得到它的人都能用 admin／public 登入並改全部設定'
                     '（帳號、規則、連接器、金鑰）。請在 HA 先改掉預設密碼再備份，或匯入後立刻改密碼。')
NO_AUTHENTICATION = ('HA 的 EMQX 沒有啟用帳號驗證，會照 HA 原樣匯入：匯入後，連得到這台 MQTT 的人不用帳號就能連線和收發訊息。'
                     '{where}如果這台另外設了公開網址（例如 Cloudflare）或 ngrok，外面的人也能連。')
IMPORT_PARTIAL = ('EMQX 匯入 HA 的資料時，有部分設定無法匯入{names}；其他資料照常匯入並已核對筆數。這些設定匯入後會缺少，請在匯入後'
                  '到這台 EMQX 的管理頁檢查並重新建立。')
ENV_WINS = ('這台 EMQX 設有 {count} 個控制帳號驗證或授權的環境變數（{names}）；它們會在匯入後的下一次啟動蓋過 HA 的設定'
            '（只列變數名稱，不列內容）。要用 HA 的設定，請先移除這些環境變數。')
CONFIG_DIFFERS = ('這台 EMQX 執行中的設定和它的設定檔不同（{names}）：多半是改過還沒重新啟動；匯入以重新啟動後的設定為準。')
FILES_MISSING = '這台 EMQX 的設定提到的檔案不在資料卷裡（{names}）；這台原本就缺這些檔案，匯入後仍然缺，請之後補上。'
TICKER_LOOSE = '暫用的 EMQX 的系統訊息沒辦法暫停，保留訊息的筆數可能差幾筆；核對時已容許這個差異，其他資料不受影響。'
RECEIPT_UNREADABLE = '讀不到這台 EMQX 內建資料庫的核對值，這次略過還原後的帳號與 ACL 規則核對；筆數在轉換時已核對過。'
BOOTSTRAP_LOST = ('這台預先建立的 MQTT 帳號（{names}）可能要在匯入後重新建立或重設密碼：{why}。' + RESET_HOW)
DIRS_FOLLOW = ('這台 EMQX 的日誌或設定目錄不是預設的位置；暫用的 EMQX 用同樣的目錄（日誌放在暫用空間，不會搬），不影響匯入。')
FILES_NOT_CARRIED = ('這台 EMQX 的設定提到 {count} 個暫用的 EMQX 帶不過去的檔案（下列設定項目）：它們放在只有執行時才有的位置、'
                     '找不到的環境變數底下或不會搬的資料夾。匯入不會搬動它們，匯入後請確認它們還在原處。')
DEVICE_INTEGRATIONS = ('這台的 EMQX 已經有自己的規則、連接器、動作、來源、橋接或閘道（共 {count} 項，列在下面）。匯入會把 HA 的加進來：'
                       '同名的以 HA 的為準{replaced}，其他的留在原處、和 HA 的一起運作（HA 的規則也可能觸發這台的連接器）。'
                       '匯入前的自動備份裡還有這台原本的設定。')
DEVICE_ROUTING = ('這台的 EMQX 已經有自己的主題改寫、主題統計、自動訂閱或 ExHook 伺服器（共 {count} 項，列在下面）。匯入後它們和 HA 的並存，'
                  '同名的以 HA 的為準{replaced}，會和 HA 的一起改寫主題或把訊息送出去。匯入前的自動備份裡還有這台原本的設定。')
DEVICE_PSK = ('這台的 EMQX 開了 PSK（預先共用金鑰）認證或設了 PSK 檔。匯入後 PSK 金鑰以 HA 的為準，這台原有的 PSK 金鑰會被取代，'
              '用它們連線的裝置要重新設定。匯入前的自動備份裡還有這台原本的金鑰。')
DEVICE_PLUGINS = ('這台的 EMQX 裝了外掛（共 {count} 個，列在下面）：外掛程式放在容器裡、不在資料卷裡，這次匯入不會搬動或改動它們，'
                  '設定裡的外掛記錄照舊保留。匯入後如果外掛沒有啟動，請到這台 EMQX 管理頁重新安裝。')
DURABLE_SESSIONS = ('這台的 EMQX 開了持久工作階段（durable sessions）。持久工作階段的資料不在 HA 的 EMQX 匯出裡，匯入會換掉這台的資料卷：'
                    '這台替離線裝置排隊的訊息會不見，裝置重新連線後要重新訂閱。匯入前的自動備份裡還有這台原本的資料。')
OUTPUT_DIR_UNUSABLE = ('EMQX 不能搬過來：這台 EMQX 把日誌或當機記錄寫在暫用的 EMQX 無法安全提供的位置（下列資料夾），已停止；'
                       '這台沒有任何改變。')
OUTPUT_DIR_ACTION = ('請先把這台 EMQX 的日誌與當機記錄路徑（log.file.*.path、node.crash_dump_file、EMQX_LOG_DIR）改回 /opt/emqx/log 底下，'
                     '再匯入 EMQX；其他應用不受影響。')
EXPOSURE_TEXT = {'local': '這台的 MQTT 埠目前只有本機能連。', 'network': '這台的 MQTT 埠目前整個區網都能連。',
                 'closed': '這台的 MQTT 埠目前沒有對外開放（只有同一個容器網路的服務能連）。'}


def _replaced_text(count):
    return f'（其中 {count} 個已經換成 HA 的）' if count else ''


def _names_text(names):
    return hacommon.names(list(names)[:10], 10) + (f' 等 {len(names)} 個' if len(names) > 10 else '')


def source_lines(sink, target, readings):
    """HA's broker's part of what the customer is told: how MQTT passwords are stored (D1: E-16..E-19, notices), the
    Dashboard account (D2, E-20, H3), the way HA treats a topic no rule matches (D0)."""
    for issue_id, message, names in plain_notices(readings):
        sink.notice(issue_id, message, names)
    if readings['default_admin']:
        places = (['開在區網上'] if exposure(target, DASHBOARD_PORTS) == 'network' else []) + (
            [f'有對外通道（{hacommon.names(target.tunnels, 5)}）'] if target.tunnels else [])
        if places:   # H3: anybody who reaches the Dashboard may take it: one line to confirm
            sink.confirm('emqx.default-dashboard-exposed', DASHBOARD_EXPOSED.format(where='，'.join(places)))
        else:
            sink.notice('emqx.default-dashboard', DASHBOARD_DEFAULT)
    rule = (readings.get('strict') or ('deny',))[0]
    sink.auto('emqx.access-from-ha', ACCESS_FROM_HA.format(rule='允許' if rule == 'allow' else '拒絕'))


def account_lines(sink, readings, device, unreadable):
    """This device's own MQTT accounts after HA's authentication replaced this device's (SR-5, E-52, E-68, E-69)."""
    if unreadable:
        sink.notice('emqx.accounts-unknown', ACCOUNTS_UNKNOWN)
        return
    off = database_off(readings, device)
    if off:   # O-3: the accounts stop for that reason, whatever HA's hashing
        sink.notice('emqx.accounts-reset', off, device['names'])
        return
    change = hash_change((readings or {}).get('hashing'), device)
    if change:
        sink.notice('emqx.accounts-reset', ACCOUNTS_STOP.format(**change), device['names'])


def candidate_lines(sink, target, readings, notes, device):
    """What the finished candidate shows, said in the check and again, with the very same names, in the conversion (the
    confirmation key covers them): E-67, S1 (E-76..E-79), S2 (E-82), D3 (E-75) and the notices of E-13, E-48, E-49, E-55,
    E-60, E-61, E-68, E-69, E-84 and H1."""
    if notes.get('rereads'):
        sink.auto('emqx.config-reread', '這台 EMQX 的設定在讀取時被改動，已重新讀取後再轉換。')
    if notes.get('dirs'):   # E-23, E-24, E-35: the candidate has this device's own folders
        sink.auto('emqx.dirs-follow-device', DIRS_FOLLOW, notes['dirs'])
    if notes.get('unreached'):   # E-29, E-30, E-32, E-50: files the settings name that the candidate cannot carry
        sink.notice('emqx.files-not-carried', FILES_NOT_CARRIED.format(count=len(notes['unreached'])), notes['unreached'])
    if notes.get('access_env'):
        sink.notice('emqx.env-wins', ENV_WINS.format(count=len(notes['access_env']), names=_names_text(notes['access_env'])),
                    notes['access_env'])
    if notes.get('differs'):
        sink.notice('emqx.config-differs', CONFIG_DIFFERS.format(names=hacommon.names(notes['differs'], 8)), notes['differs'])
    if notes.get('missing'):
        sink.notice('emqx.target-file-missing', FILES_MISSING.format(names=_names_text(notes['missing'])), notes['missing'])
    if notes.get('partial'):
        names = [name for name in notes['partial'] if name]
        sink.confirm('emqx.import-partial', IMPORT_PARTIAL.format(names=f'（{hacommon.names(names, 8)}）' if names else '（無法判斷是哪幾項）'),
                     names)
    security = notes.get('security') or {}
    if security.get('file_secret'):
        sink.confirm('emqx.file-secret', FILE_SECRET.format(count=len(security['file_secret']),
                                                            names=_names_text(security['file_secret'])), security['file_secret'])
    if security.get('jq_rule'):
        sink.confirm('emqx.jq-rule', JQ_RULE.format(count=len(security['jq_rule']), names=_names_text(security['jq_rule'])),
                     security['jq_rule'])
    if security.get('external_authn'):
        sink.confirm('emqx.external-authn', CREDENTIAL_RECEIVER.format(what='外部帳號驗證', names=_names_text(security['external_authn'])),
                     security['external_authn'])
    if security.get('external_authz'):
        sink.confirm('emqx.external-authz', AUTHZ_RECEIVER.format(names=_names_text(security['external_authz'])),
                     security['external_authz'])
    if security.get('exhook'):
        sink.confirm('emqx.exhook', CREDENTIAL_RECEIVER.format(what='啟用的 ExHook 伺服器', names=_names_text(security['exhook'])),
                     security['exhook'])
    own = notes.get('device_items') or {}   # E-41, E-42, E-43, E-44, E-47: this device's own, next to HA's
    replaced = own.get('replaced') or {}
    if own.get('integrations'):
        sink.confirm('emqx.device-integrations', DEVICE_INTEGRATIONS.format(
            count=len(own['integrations']), replaced=_replaced_text(replaced.get('integrations'))),
            haissues.Names(own['integrations']))
    if own.get('routing'):
        sink.confirm('emqx.device-routing', DEVICE_ROUTING.format(
            count=len(own['routing']), replaced=_replaced_text(replaced.get('routing'))), haissues.Names(own['routing']))
    if own.get('psk'):
        sink.confirm('emqx.device-psk', DEVICE_PSK, haissues.Names(own['psk']))
    if own.get('durable'):
        sink.confirm('emqx.durable-sessions', DURABLE_SESSIONS, haissues.Names(own['durable']))
    if own.get('plugins'):
        sink.notice('emqx.device-plugins', DEVICE_PLUGINS.format(count=len(own['plugins'])), haissues.Names(own['plugins']))
    if notes.get('anonymous') and notes.get('device_authenticated'):
        where = EXPOSURE_TEXT[exposure(target, MQTT_PORTS)]
        if target.tunnels:
            where += f'這台另有對外通道（{hacommon.names(target.tunnels, 5)}），外面的人也可能連得到。'
        sink.confirm('emqx.no-authentication', NO_AUTHENTICATION.format(where=where))
    if notes.get('acl_replaced'):
        sink.notice('emqx.acl-replaced', ACL_REPLACED.format(names=_names_text(notes['acl_replaced'])), notes['acl_replaced'])
    reasons = set(notes.get('bootstrap') or ())
    if notes.get('lost') or reasons:
        why = []
        if notes.get('lost'):
            why.append('這台 bootstrap 帳號檔的類型、位置或掛載方式無法跟著匯入，或暫用的 EMQX 讀不到它')
        if 'ha-authn' in reasons:
            why.append('HA 的帳號驗證和這台的 bootstrap 帳號檔對不上（HA 的內建資料庫認證停用或用 clientid 當帳號）')
        if 'hash' in reasons:
            why.append('這台的 bootstrap 帳號檔是 hash 格式，和 HA 的雜湊方式不同')
        names = list((device or {}).get('names') or [])
        sink.notice('emqx.bootstrap-lost', BOOTSTRAP_LOST.format(names=_names_text(names) if names else '例如 woow',
                                                                  why='；'.join(why)), names)
    if notes.get('ticker') is False or (readings is not None and readings.get('ticker') is False):
        sink.notice('emqx.sys-ticker', TICKER_LOOSE)
    if notes.get('receipt_unreadable'):
        sink.notice('emqx.receipt-unreadable', RECEIPT_UNREADABLE)


def check_warnings(src, readings):
    """The reminders that stay sentences (the page shows them as notices): HA's own addresses, files outside HA's data
    folder, plugins that do not move, API keys that replace this device's, a backup made while EMQX ran."""
    warnings = []
    if readings is not None and readings['counts'].get('emqx_app', 0) > 0:
        warnings.append('HA 的 EMQX API 金鑰會取代這台的，EMQX MCP 管理需要重新登入。')
    warnings += hocon_notes(src.hocon)
    if src.plugins:
        warnings.append(f'HA 的 EMQX 外掛（{hacommon.names(sorted(src.plugins))}）不會搬過來，需要時請在這台重新安裝。')
    if hint_for(src.addon):
        warnings.append('這份 HA 備份是在 EMQX 執行中製作的；最近的變更可能還沒寫進內建資料庫。最可靠的做法是先在 HA 停止 EMQX '
                        '附加元件再製作備份。')
    return warnings


class Built:
    """What `_build_candidate` made: HA's side (`src`, `node`, `readings`), the export file, the row counts, the strict rule,
    the readback of the finished candidate and `notes` (candidate_lines' facts)."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


def _build_candidate(work, app, tmp, target, staging, *, version, src=None, node=None, sink=None, device=None,
                     unreadable=False, chosen=None, phase='convert'):
    """The check's and the conversion's build (also driven by the lab harnesses); never replaces live volumes.

    HAOS parity: the same candidate is built in the check (H7, DESIGN H-6: +1-2 minutes; `sink` collects) and in the
    conversion (`sink` raises `confirmation-required` for a line the customer did not confirm), and everything the customer
    is told is read from the finished candidate by the same functions (candidate_lines): the names, and so the key, are the
    same. HA's authentication and authorization are HA's in it (D0, apply_ha_access), this device's other settings are
    its own, HA's tables are checked row by row.
    Returns a `Built`."""
    sink = work.sink(app) if sink is None else sink
    # Internal test-owner diagnostics receive fixed stages only, never source values or exception text. Ordinary product
    # callers have no observer.
    observe=getattr(work,'_emqx_build_stage',None)
    def stage(name):
        if observe is not None:observe(name)
    stage('version')
    if src is None:
        stage('member_pass')
        src = member_pass(work, tmp)
    work.phase(phase)
    stage('node_name')
    if node is None:
        node, _rows, said = pick_node(src, chosen if chosen is not None else work.choice(app.id, 'node'))
        if said:
            sink.auto('emqx.node-chosen', said, [node])
    stage('source_broker')
    readings = ha_broker(work, tmp, target, src, node, out_dir=staging)
    stage('source_analysis')
    source_lines(sink, target, readings)
    if device is not None or unreadable:
        account_lines(sink, readings, device, unreadable)
    tmp.stop('emqx-ha', timeout=60)
    tmp.remove('emqx-ha')
    stage('source_export')
    export = take_export(work, tmp, readings['export'], staging)
    _clean(tmp, volumes=('emqx-src', 'emqx-xfer', 'emqx-ha-log'))
    emqx_ids = tmp.user_ids('ids-emqx', target.image, 'emqx')
    stage('target_candidate')
    notes = {}
    seeded, counts, strict, _live_authn = candidate_from_target(
        work, app, tmp, target, staging, export, emqx_ids, hint=hint_for(src.addon), readings=readings, notes=notes)
    stage('row_counts')
    loose = ('emqx_retainer_message',) if not (readings.get('ticker') and notes.get('ticker', True)) else ()
    problems = check_counts(readings['counts'], seeded, counts, loose=loose,
        observe=(lambda table, direction: stage('row_counts_'+table+'_'+direction)) if observe is not None else None)
    if problems:
        raise BackupError('job-failed', f'EMQX 匯入後的資料筆數和 HA 不同，已停止：{"、".join(problems[:10])}。')
    readback = candidate_readback(tmp, notes=notes)
    write_marker(tmp)
    candidate_lines(sink, target, readings, notes, device)
    return Built(src=src, node=node, readings=readings, export=export, counts=counts, strict=strict, live_authn=_live_authn,
                 readback=readback, notes=notes)


def check(work, app):
    """The check. HAOS parity: it builds the candidate the conversion builds (H7), so everything the customer must confirm
    -- and what makes the app unable to import -- is known before anything is converted; `choices.node` offers HA's
    databases when the backup does not say which one it used (E-07, E-09)."""
    sink = work.sink(app)
    tmp = work.temp(app)
    target, version = _prepare(work, app)
    ensure_target_running(work, app, target)   # E-22: a stopped EMQX is started to be read (and put back)
    version = version_lines(sink, work, app, target, version)
    device, unreadable = read_device(work, app, target)
    src = member_pass(work, tmp)
    work.phase('check')
    node, rows, said = pick_node(src, work.choice(app.id, 'node'))
    if said:
        sink.auto('emqx.node-chosen', said, [node])
    staging = work.staging / 'emqx-work'
    staging.mkdir(mode=0o700, exist_ok=True)
    built = _build_candidate(work, app, tmp, target, staging, version=version, src=src, node=node, sink=sink,
                             device=device, unreadable=unreadable, phase='check')
    _clean(tmp, 'emqx-new', volumes=('emqx-new', 'emqx-new-log', 'emqx-in'))
    if built.export and os.path.exists(built.export):
        os.unlink(built.export)
    found = {'target_version': version or '', 'warnings': check_warnings(src, built.readings),
             'emqx': section(src, node, built.readings, version=version)}
    if rows:
        found['choices'] = {'node': rows}
    return found


def _package_candidate(work, tmp, target, staging, out_dir, export, *, ids, log_root):
    """Package isolated candidate volumes; does not install or modify target volumes."""
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    code = tmp.stop('emqx-new', timeout=120)
    if code not in (0, 143):
        raise BackupError('job-failed', f'暫用的 EMQX 沒有正常關閉（結束碼 {code}）。')
    tmp.remove('emqx-new')
    raw = staging / 'emqx-new.tar'
    with open(raw, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.volume_export('emqx-new', handle, max_output=work.guard.budget())
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    out = hacommon.FileTar(data_path, work.guard)
    try:
        data_volume(raw, out)
    finally:
        out.close()
    os.unlink(raw)
    os.unlink(export)
    log_path = out_dir / 'volumes' / f'{target.log_volume}.tar'
    tar = hacommon.FileTar(log_path, work.guard)
    try:
        hacommon.top_only(tar, log_root)
    finally:
        tar.close()
    for path in (data_path, log_path):
        ha_odoo.check_volume_tar(path, ids)
    _clean(tmp, volumes=('emqx-new', 'emqx-new-log', 'emqx-in'))
    return {target.data_volume: data_path, target.log_volume: log_path}


def convert(work, app, test_mode, out_dir):
    """This device's volumes from HA's data: HA's authentication and authorization with HA's tables, this device's own
    settings otherwise, verified (_build_candidate); the result carries the readback the restore compares (`import_check`,
    CONTRACT section 9). A line of the confirmation the customer did not confirm with exactly its names stops only this app
    (`confirmation-required`) before anything is packaged."""
    adapter = work.adapter(app)
    tmp = work.temp(app)
    sink = work.sink(app)
    target, version = _prepare(work, app)
    ids = adapter.owner_ids()
    staging = work.staging / 'emqx-work'
    staging.mkdir(mode=0o700, exist_ok=True)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    ensure_target_running(work, app, target)
    version = version_lines(sink, work, app, target, version)
    device, unreadable = read_device(work, app, target)   # SR-5: the check's read, again
    built = _build_candidate(work, app, tmp, target, staging, version=version, sink=sink, device=device,
                             unreadable=unreadable)
    # HA's rule (the real run on dev-d, 2026-11-25, printed this device's own, read before the import): what the restored broker
    # does with a topic no rule matches is what HA's did.
    rule = (built.readings.get('strict') or built.strict)[0]
    work.log(f'EMQX 資料匯入完成：{len(TABLES)} 個資料表的筆數都符合 HA；「沒有符合規則的主題時」的處理已改成 HA 的「'
             f'{"允許" if rule == "allow" else "拒絕"}」')
    work.log('EMQX 的帳號驗證與授權來源（含 ACL 檔案）已改成 HA 的，這台的位址、連接埠與其他設定已核對保留')
    volumes = _package_candidate(work, tmp, target, staging, out_dir, built.export, ids=ids,
                                 log_root=ha_n8n.volume_root(work, app, target.log_volume))
    readings = built.readings
    return {'volumes': volumes, 'node': built.node,
            'ha_hosts': hacommon.ha_hosts(built.src.hocon), 'plugins': sorted(built.src.plugins),
            'anonymous': not any(a['enable'] for a in readings['authn']),
            'hash_change': hash_change(readings['hashing'], device),
            'api_keys': max(readings['counts'].get('emqx_app', 0), 0),
            'import_check': built.readback}


# ====================================================================== texts

# D0 (4), DESIGN H-c: HA's add-on options (the `env_vars` page of the EMQX add-on: the customer's own EMQX_* settings) are not in
# what the reader hands out (habackup: addon.json and data/options.json are never read), so HA's throwaway broker starts
# without them and nothing of them is moved. The customer is told, once, after the import; there is no way to say whether
# the add-on had any.
OPTIONS_NOT_MOVED = ('HA 的 EMQX 附加元件頁的選項（例如自己設的 EMQX_ 環境變數 env_vars）沒有搬過來：備份工具不讀附加元件的選項檔，'
                     '也無法得知您有沒有設過。如果您在 HA 設過，請在匯入後到這台 EMQX 的環境設定檔補上。')

def import_texts(data):
    notes = ['EMQX 的 MQTT 帳號、ACL 規則、Dashboard 帳號、API 金鑰、封鎖名單、PSK、保留訊息，以及帳號驗證、授權來源（含 ACL 檔案）、'
             '「沒有符合規則的主題時」的處理、規則和連接器設定，都換成 HA 的（和 HAOS 還原一樣）；這台的節點名稱、連接埠、位址和其他'
             '設定保持不變。',
             '還原後會再核對 MQTT 帳號、ACL 規則和金鑰都和轉換時相同，不同就自動回復。']
    reminders = ['請把 MQTT 裝置與服務（例如 Home Assistant 的 MQTT 整合、Zigbee2MQTT）改連到這台的 EMQX。',
                 '匯入後請用 HA 那邊的 EMQX Dashboard 帳號和密碼登入。',
                 OPTIONS_NOT_MOVED]
    if data.get('anonymous'):
        reminders.append('HA 的 EMQX 沒有啟用帳號驗證，匯入後這台也一樣：連得到這台 MQTT 的人不用帳號就能連線。')
    change = data.get('hash_change')
    if change:   # SR-5: the check page named these accounts before the conversion; the restore step repeats it
        notes.append(f'HA 的 EMQX 保存 MQTT 密碼的方式（{change["ha"]}）和這台（{change["mine"]}）不同，匯入後以 HA 的為準：'
                     f'這台原本的 MQTT 帳號（{change["names"]}）無法再用原本的密碼登入。')
        reminders.append(f'請重新設定這台原本的 MQTT 帳號（{change["names"]}）：{RESET_HOW}')
    if data.get('ha_hosts'):
        reminders.append(f'HA 的 EMQX 規則或連接器連到 HA 內部的位址（{hacommon.names(data["ha_hosts"], 8)}），請改成這台連得到的位址。')
    if data.get('plugins'):
        reminders.append(f'HA 的 EMQX 外掛（{hacommon.names(data["plugins"])}）沒有搬過來，需要時請在這台重新安裝。')
    if data.get('api_keys'):
        reminders.append('HA 的 EMQX API 金鑰已取代這台的，使用這台 EMQX API 的工具需要換成新的金鑰。')
    return notes, reminders
