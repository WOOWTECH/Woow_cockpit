# parity-pkg-20261125 (proposed place: tests/backup/evidence/parity-pkg-20261125/README.md, raw files: evidence/ next to this snippet)

Rows KEY-14, KEY-15, X-AR-06, X-KEY-02: branch parity/pkg-20261125 on e7d687b. Changed files: scripts/bootstrap-ubuntu.sh,
scripts/manage.py, tests/test_manage.py. No engine or page file. commercial_acceptance: not-complete.
Iteration 1: 38be68a, e028d12, dd491d9, 18e5c36. Iteration 2: 871cf82 (WIP of the stopped agent, the base of this work), 5a7125b,
b2e5ee5, 5a2fd25 (last product change), 8536def, e7fcc82 (tip; tests only).

What iteration 2 changed (decision of the main session 2026-11-25 09:35 + the verifier's findings of iteration 1)
1. An offline device is NOT refused its update. When the missing packages cannot be added, manage.py install goes on and reports one
   zh-TW notice (names, reason, what cannot be done meanwhile, what to do; JSON: missing_packages, notices; also printed as Note:);
   manage.py status then lists what is missing and exits 1; install exits 0. --no-backup, --root, a source without the engine: unchanged.
2. Wording about bootstrap-ubuntu.sh narrowed: the relaxed checks concern the four backup packages only. The step of the five Cockpit
   packages is as before and still needs the network when something has to be downloaded (test_the_cockpit_packages_step_is_as_before...).
3. status looks at the engine that is on the device, also after --no-backup (it said "ready" with tools missing); says it needs sudo.
4. The plan (desired files, Cockpit and cockpit-podman checks) is made again after the package step (apt-get may wait minutes for the
   dpkg lock of an automatic update): what another job changed meanwhile is not overwritten. What the installer refuses by itself is
   still refused before apt-get runs.
5. Reasons told from what apt wrote: no network (a proxy login and a captive portal included) / universe not enabled or no source has the
   package / broken third-party source (404, unreachable, unreadable list) / package gone or mirror being synchronised / lists or dpkg
   locked / signature or validity of a source (no key, not signed, expired, not valid yet); also interrupted dpkg, disk, held package,
   conflict, unmet dependencies, apt-get cannot run. What apt's lines do not prove is called 原因不明 with the exit code. Never apt's lines.
6. A test that really runs the probes (a misspelled import or name fails it) and the raw evidence below.

| what | result | kind |
| --- | --- | --- |
| tests.test_manage | 81 OK (49 at the base, 67 after iteration 1) | unit tests: a fake apt, stub commands for the bootstrap script; the apt texts it replays are real recordings |
| the 8 top-level unit modules through guard.py on e7fcc82 (suites-e7fcc82.txt) | 153 tests, 0 failures, 0 errors, 0 skipped, 0 blocked | unit tests |
| full tests/backup --b1 through guard.py on 5a2fd25 (suites-5a2fd25.txt, b1-failures-5a2fd25.txt) | 1876 tests; not ok = exactly the 5 known test_litellm_lab_runner guard refusals (blocked 6), as on e7d687b and dd491d9 | unit tests; not repeated on e7fcc82: 5a2fd25..e7fcc82 changes only tests/test_manage.py, which tests/backup does not read |
| mutation sweep 1 on 5a2fd25 (mutations-5a2fd25.*) | 129 mutations: 124 caught, 5 survived; both controls (a comment, a docstring) unnoticed | mutations of scripts/manage.py and bootstrap-ubuntu.sh |
| mutation round 2 on e7fcc82 (mutations-e7fcc82-round2.*) | 26 of 26 caught: the 5 survivors (each got a test) and one mutation per alternative of the apt message patterns; both controls unnoticed | idem |
| so | 150 distinct mutations, all caught. Round 1 was run before the five tests were added; they only add tests and no product file changed between 5a2fd25 and e7fcc82 | |
| the real probes on the development host, read-only (as the installer runs them) | all five answer: age, age-keygen, zstd, python3-nacl, python3-cryptography | real, read-only |
| stand-in package trees for the python probes | complete passes, each name missing fails, the cryptography decryptor must be called | real interpreter, stand-in packages |
| real apt-get 2.8.4 in a private unprivileged apt root with a local repository and a dpkg stub (real-apt/, 34 cases, README.txt) | the reason of every class above comes from these outputs; 26 are embedded verbatim in the tests (APT_RECORDED) | real apt-get, but not the Ubuntu archive, not a device, dpkg is a stub |
| real apt-get 2.8.4 and the real Ubuntu archive in a private apt root (real-ubuntu-archive.*) | 4 packages and their dependencies added, every probe answers, the second call runs nothing | real apt-get and archive; dpkg is an unpacking stub, no dpkg database, no root |
| manage.py status as a normal user on this host | says it needs sudo (does not read the root-owned install record) | real, read-only |
| bootstrap-ubuntu.sh --plan on this host | lists the nine packages as installed | real, read-only |

Not done (REAL lane): manage.py install on a device that really lacks packages, with and without the network (dpkg -r python3-nacl,
manage.py status, manage.py install; offline: the notice and the finished update); the 300 s wait for the dpkg lock (the recording
used 2 s); "No space left on device" and "Packages need to be removed" were not provoked (apt catalogue texts, tested one by one).
Iteration 1's evidence is kept under iteration1-*.  The first sweep of iteration 1 (62 mutations, 61 caught, the survivor closed by a
test) was overwritten when it was repeated with 66; what is kept is that repeat (iteration1-mutations-e028d12.json).

Consequences the owner should know (not blockers)
- An offline device that lacks one of the four packages now gets the whole Cockpit update; importing an encrypted HA backup (or any
  encrypted backup) then stops at run time with the engine's own message until the packages are there. The install said so up front.
- apt-get has no time limit and uses its default network time-outs: on a network that silently drops packets the package step can take a
  few minutes before the update goes on (the Note says "可能要幾分鐘").
- bootstrap-ubuntu.sh still stops when a missing backup package cannot be installed (it is the package installer); manage.py install
  is the one that goes on. If the owner wants the bootstrap to enable cockpit.socket first and report the failure at the end, it is a
  small change in that script.
