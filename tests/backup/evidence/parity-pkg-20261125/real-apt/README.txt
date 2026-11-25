# Real apt-get runs behind the reason texts of scripts/manage.py (lane PKG, 2026-11-25)

What this is: the REAL /usr/bin/apt-get 2.8.4 (Ubuntu 24.04, C locale), started by manage.HostTools.ensure() with exactly its argv
and environment, in a private unprivileged apt root (record.py / lib.py): a local HTTP repository with four dummy packages
(age, zstd, python3-nacl, python3-cryptography; some cases use the layout of the Ubuntu archive, dists/noble/ + pool/), dpkg replaced
by a stub that only logs and unpacks, no root, nothing outside the private root is touched. In these runs every probe answers
"does not work", so ensure() always goes through apt and the reason text is produced. Host names are replaced: 127.0.0.1 is
repo.example, 127.0.0.2 the third-party host; ports 80; the private root is <root>; the id of the throwaway test key that signs the
signature cases is masked (NO_PUBKEY 0000000000000000). Nothing else was edited: every line is as apt wrote it.
26 of these cases are embedded verbatim in tests/test_manage.py (APT_RECORDED, made by make_fixture.py); the others are kept as
raw files only (flat or archive layout variants, and runs where apt succeeded).

Per case: case.txt (what was set up), update.argv/rc/out/err and install.argv/rc/out/err (the two apt-get runs), notice.txt (the
zh-TW notice the code makes from them; made again offline from the recorded files with the code of 5a2fd25 by renotice.py, because
the wording of the sentence around the reason was refined after record.py had run: the apt files are as recorded). Re-run: python3 record.py <worktree> [case ...] (needs gpg, apt-ftparchive, dpkg-deb).
The lock case shortens the dpkg lock wait of the RECORDING to 2 s (LOCK_TIMEOUT; the product waits 300 s); update.argv shows the
real argv, the "(ran with ...)" line says what was run.

Not provoked here (their text comes from apt's own message catalogue, checked against its translation files): "No space left on
device" (libc text of ENOSPC) and "Packages need to be removed but remove is disabled" (the one conflict tried ended as
"unable to correct problems, you have held broken packages", recorded as `conflict`).

Where install rc is 0 apt added the packages (or, for the damaged-offline-no-index case, could not reinstall and said so with
exit code 0, on stdout); the sentence in the last column is then only an artifact of this harness, whose probes always answer
"does not work": the real flow does not make a notice when the probes answer afterwards.

| case | what was set up | update rc | install rc | the reason in the notice |
| --- | --- | --- | --- | --- |
| captive-portal | every address answers 200 with a login page | 100 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| conflict | age conflicts with an installed package: apt would have to remove it | 0 | 100 | 和已安裝的套件衝突，要移除或更換已安裝的套件才能裝，這裡不會自動移除 |
| damaged-offline-no-index | the packages are installed (a tool does not answer), no index, the repository is not reachable | 0 | 0 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| damaged-offline-old-index | installed, old index, repository not reachable: a reinstall needs a download | 0 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| damaged-online | installed, index and files reachable: a reinstall works | 0 | 0 | 套件已經裝好，但這個工具仍然沒有正常回應（status 會顯示是哪一個） |
| disk-full | the index says the packages are enormous: not enough free space in the apt cache | 0 | 100 | 磁碟空間不足 |
| dists-offline-old-index | archive layout (noble main universe): index downloaded earlier, the archive is not reachable now | 0 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| dists-release-expired | archive layout: InRelease says Valid-Until in the past | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
| dists-release-not-valid-yet | archive layout: InRelease is dated in the future (the clock is wrong) | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
| dists-signature-no-key | archive layout: signed, apt has no key for it | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
| dists-universe-off | archive layout: "noble main" only, age lives in universe | 0 | 100 | 這台啟用的套件來源沒有 age，或設定把它排除了（age 在 Ubuntu 的 universe，可用 sudo add-apt-repository universe 啟用） |
| dpkg-fails | dpkg ends with an error while it installs | 0 | 100 | 原因不明（apt-get 結束碼 100） |
| dpkg-interrupted | dpkg has a half-done job (updates/ is not empty) | 0 | 100 | 上一次的套件安裝沒有完成，請先執行 sudo dpkg --configure -a |
| held | age is installed at an older version and apt-mark hold keeps it | 0 | 100 | 套件被鎖定（apt-mark hold），不會自動變更 |
| locked | another process holds the lock of the package lists and the dpkg frontend lock | 100 | 100 | 另一個套件作業（例如系統自動更新）正在進行，請等它完成 |
| no-sources | no package source is configured at all | 0 | 100 | 這台啟用的套件來源沒有 age、zstd、python3-nacl、python3-cryptography，或設定把它排除了（Ubuntu 的 main 與 universe 都要啟用） |
| offline-dns | a source whose name does not resolve (.invalid), no index | 0 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| offline-no-index | closed port, no package index was ever downloaded | 0 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| offline-old-index | the index was downloaded earlier, the repository is not reachable now, no .deb cached | 0 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| ok-then-works | everything reachable (the probes of this harness still say "does not work") | 0 | 0 | 套件已經裝好，但這個工具仍然沒有正常回應（status 會顯示是哪一個） |
| package-gone | the index lists the packages, the files are gone from the server (404) | 0 | 100 | 套件庫已經沒有這台索引記的版本（索引太舊或套件庫正在同步），請先讓 sudo apt-get update 成功 |
| proxy-407 | a proxy asks for a login (407) | 100 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| proxy-down-old-index | old index; the administrator proxy (http_proxy) does not answer | 0 | 100 | 這台連不到套件庫（網路、DNS、代理伺服器，或要先登入的網路） |
| release-expired | the Release file says Valid-Until in the past | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
| release-expired-old-index | an earlier good index; the repository now serves an expired Release | 0 | 0 | 套件已經裝好，但這個工具仍然沒有正常回應（status 會顯示是哪一個） |
| release-not-valid-yet | the Release file is dated in the future (the clock of this device is wrong) | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
| signature-no-key | the repository is signed, apt has no key for it, no earlier index | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
| sources-unreadable | a file in sources.list.d is malformed | 100 | 100 | 套件來源的設定檔有錯，apt 讀不了（/etc/apt/sources.list 或 sources.list.d，常見是第三方來源） |
| third-party-404 | age is not in the reachable index and a third-party source answers 404 (its repository was removed) | 100 | 100 | 有套件來源無法更新（網址不存在），其他來源沒有 age：請用 sudo apt-get update 找出並修正那個來源，也請確認已啟用 universe |
| third-party-404-but-packages-available | a broken third-party source while the main source has every package: installs | 100 | 0 | 套件已經裝好，但這個工具仍然沒有正常回應（status 會顯示是哪一個） |
| third-party-down | age is not in the reachable index and a third-party source cannot be reached | 0 | 100 | 有套件來源無法更新（連不上），其他來源沒有 age：請用 sudo apt-get update 找出並修正那個來源，也請確認已啟用 universe |
| universe-off | the reachable index has zstd and the python packages but not age | 0 | 100 | 這台啟用的套件來源沒有 age，或設定把它排除了（age 在 Ubuntu 的 universe，可用 sudo add-apt-repository universe 啟用） |
| unmet-dependencies | a package depends on one that no source has | 0 | 100 | 相依的套件湊不齊（缺少、版本不合或被鎖定） |
| unsigned-source | a repository without any signature and without [trusted=yes]: apt does not take its index | 100 | 100 | 套件來源的簽章或有效期限驗證不過（金鑰、這台的時間或來源設定不對） |
