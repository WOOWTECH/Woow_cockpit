# 備份與還原實驗室設備（team L）

兩台彼此隔離、接近實機的 Ubuntu 24.04「設備」，供備份與還原端到端測試使用。每台設備是一個以
systemd 為 PID 1 的 rootless 容器，內含 Cockpit 362、rootless Podman（巢狀）、age、zstd 與 python3。
**所有容器操作只透過 `~/.woowbk-lab/bin/labpodman`**（獨立儲存根目錄 `~/.woowbk-lab/storage`），
正式主機的容器、資料卷、映像與服務在這裡完全看不到，也不會被影響。不使用 sudo。

## 設備規格

| 項目 | woowbk-dev-a | woowbk-dev-b |
| --- | --- | --- |
| Cockpit（HTTPS，自簽憑證） | https://127.0.0.1:19091 | https://127.0.0.1:19092 |
| 主機名稱 | `woowbk-dev-a` | `woowbk-dev-b` |
| appowner UID／GID | 1001 | 1007 |
| machine-id | 每台不同（首次開機由 podman 的 `container_uuid` 產生；重建容器會改變） | 同左 |
| 管理員 | `devadmin`（UID 1000，sudo 群組，Cockpit 登入，密碼見下） | 同左 |
| 資源上限 | `--memory 768m --cpus 1.5` | 同左 |
| 資料卷 | `woowbk-dev-a-home`→`/home`、`-varlib`→`/var/lib/woowtech-backup`（0700）、`-containers`→`/var/lib/containers` | `woowbk-dev-b-…` |
| 預設狀態 | 已部署並植入 woowbk-demo（執行中） | 只有 appowner，**未部署**應用（跨設備還原目標） |

`devadmin` 密碼由 `up.sh` 以 `openssl rand -hex 16` 產生一次，存於
`~/.woowbk-lab/secrets/devadmin.pass`（0600），每次 `up.sh` 由標準輸入設定到設備內，不出現在參數或日誌。

### 映像 `localhost/woowbk-device:noble`

`Containerfile.device`：`FROM docker.io/library/ubuntu:24.04`（設備內為 Ubuntu 24.04.5 LTS；參考主機為
24.04.4），固定 apt 來源 noble／updates／backports／security。實際安裝版本（`/etc/woowbk-device-versions`）：

| 套件 | 版本 |
| --- | --- |
| cockpit-ws／cockpit-bridge／cockpit-system | 362-1~bpo24.04.1（noble-backports，與正式主機相同） |
| podman | 4.9.3+ds1-1ubuntu0.2 |
| crun／conmon | 1.14.1-1／2.1.10+ds1-1build2 |
| netavark／aardvark-dns | 1.4.0-4／1.4.0-5 |
| slirp4netns／passt／fuse-overlayfs／uidmap | 1.2.1-1build2／0.0~git20240220.1e6f92b-1／1.13-1／1:4.13+dfsg1-4ubuntu3.2 |
| age／zstd／python3 | 1.1.1-1ubuntu0.24.04.3／1.5.5+dfsg2-2build1.1／3.12.3-0ubuntu2.1 |
| systemd／sudo | 255.4-1ubuntu8.18／1.9.15p5-3ubuntu5.24.04.4 |

映像約 238 MB。appowner 不在映像內，而是 `up.sh` 開機後由 `/usr/local/sbin/woowbk-provision` 依設備建立
（因此兩台可用不同 UID）。

## 指令

| 指令 | 作用 |
| --- | --- |
| `build.sh [--no-cache]` | 以 labpodman 建置映像（`--memory 768m`），並列出套件版本 |
| `up.sh <a\|b>` | 建立或啟動設備，等到 systemd 開機完成、`cockpit.socket` 監聽 9090、`user@<uid>.service` 啟用；設定 devadmin 密碼、appowner、subuid/subgid、linger。啟動前檢查主機可用記憶體 ≥ 1200 MB |
| `down.sh <a\|b\|all> [--rm]` | 停止設備（保留容器與資料卷）；`--rm` 另移除容器但保留資料卷 |
| `reset.sh <a\|b> [--up]` | 刪除設備**與其所有資料卷**（含巢狀映像、應用資料、備份）；`--up` 隨即重建 |
| `exec.sh <a\|b> [cmd…]` | 以 root 在設備內執行（預設互動 shell） |
| `owner.sh <a\|b> cmd…` | 以 appowner 執行，方式與引擎相同（`runuser -u appowner -- env -i … XDG_RUNTIME_DIR=/run/user/<uid> DBUS_SESSION_BUS_ADDRESS=…`） |
| `engine.sh <a\|b> <command> [json\|-]` | 以 root 呼叫 `/usr/local/libexec/woowtech-cockpit-backup`，輸出單一 JSON 並遮蔽 `key`／`content` 字串；帶金鑰的請求用 `-` 由標準輸入提供 |
| `deploy-src.sh <a\|b> [--fallback]` | 把**目前工作樹**（排除 `.git node_modules .local design __pycache__`）複製到設備 `/opt/woow-cockpit-src`（root 擁有、不可群組／其他人寫入），安裝程式支援時執行 `manage.py install --backup-demo-catalog`；尚不支援時結束碼 3，`--fallback` 執行檔頭記載的實驗室專用手動安裝 |
| `deploy-demo.sh <a\|b> [--notes N] [--files M] [--title T] [--no-seed]` | 不經引擎、以 appowner 手動部署 woowbk-demo（拉取 postgres、建置應用映像、安裝 Quadlet、daemon-reload、seed） |
| `verify-device.sh <a\|b> [--no-browser]` | 實測：systemd `running`、Cockpit socket、user manager、巢狀 podman（alpine、uid map、`--memory`）、Quadlet 產生器、Playwright 登入並開啟管理員存取 |
| `cockpit-login.mjs <a\|b>` | Playwright：HTTPS 登入 devadmin → 開啟管理員存取 → `cockpit.spawn(['id','-u'], {superuser:'require'})` 必須為 0；截圖存於 `~/.woowbk-lab/evidence/lab/`（只在未輸入密碼或密碼欄消失後截圖） |
| `status.sh` | 兩台設備的狀態、systemd、記憶體、示範應用 `/healthz` |

離線夾具測試：`python3 -B -m unittest discover -s tests/e2e -p 'test_*.py' -v`。

### 典型流程

```bash
tests/e2e/lab/build.sh
tests/e2e/lab/up.sh a && tests/e2e/lab/up.sh b
tests/e2e/lab/verify-device.sh a && tests/e2e/lab/verify-device.sh b
tests/e2e/lab/deploy-demo.sh a --notes 12 --files 4          # 只在 dev-a
tests/e2e/lab/deploy-src.sh a && tests/e2e/lab/deploy-src.sh b  # 安裝引擎、介面與 woowbk-demo 受信任設定
tests/e2e/lab/owner.sh a python3 /opt/woowbk-demo/tools/check.py --stop-start
```

## 端到端測試（整合）

兩個執行器都只透過 labpodman 操作設備，結果與截圖寫入 `~/.woowbk-lab/evidence/integration/<時間>-<情境>/`
（`driver.log`、`result.json`、作業紀錄）。金鑰與密碼只從 `~/.woowbk-lab/secrets/`（0600）讀取，不會出現在輸出或證據中。

| 指令 | 內容 |
| --- | --- |
| `python3 -I tests/e2e/lab/cli_e2e.py all` | 以頁面相同的方式呼叫**已安裝**的 helper（root、stdin JSON、單一 JSON 回應）；下載／上傳走設備內真正的 `cockpit-bridge`（`fsread1`、`fsreplace1`＋`send-acks`、512 KiB、≤ 4 MiB 未確認）。情境：`s1`（dev-a 金鑰、植入、含映像備份、F10 去重與 busy、變更、原位還原）、`s2`（先把 dev-b 重設為全新目標；A 下載 → B 上傳、key-required、F1 錯誤金鑰、緊急金鑰、全新部署還原、還原後可寫入）、`faults`（F2 截斷、F3 翻轉位元、F4 非備份檔與新版格式、驗證作業、F12 非 root）、`s3`（不含映像的備份在沒有本機映像的設備預檢失敗、不留任何東西）、`s2-again`、`f8`（破壞性步驟後失敗 → 自動回復，資料等於還原前）、`f9`（SIGKILL 還原 → interrupted、以還原前備份還原）、`leaks`（作業紀錄、日誌、索引、journal 沒有密鑰或金鑰）。dev-a 的緊急金鑰（實驗室拋棄式）存於 `~/.woowbk-lab/secrets/dev-a-kit.txt` |
| `node tests/e2e/lab/ui_e2e.mjs all` | 以 Playwright 登入真正的 Cockpit 362（devadmin），操作已安裝的「備份與還原」頁面：`admin`（受限存取 → 需要管理員權限；切換後載入真實資料，F12）、`s1`（頁面建立含映像備份、作業中關閉分頁再開啟會回到作業（F11）、經 cockpit-ws 外部 `fsread1` 通道下載並核對 SHA-256、從列表原位還原、結果表「資料一致」）、`s2`（dev-b 重設後由頁面上傳（websocket `fsreplace1`）、金鑰步驟、預檢 UID 1007、全新部署、可寫入）。需要 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 或 `~/.cache/ms-playwright/chromium-1248` |

重設 dev-b 只做擁有者層級的移除（停止服務、刪除 Quadlet、資料卷、密鑰、設定檔與示範應用映像）並刪除 dev-b 的備份，
不重建設備。

## 強化測試（hardening，H1–H8 與發布回歸情境）

`python3 -I tests/e2e/lab/hardening.py <h1|h2|h3|h4|h5|h6|h7|sec1|fidelity|fresh|leaks|all>` 與
`node tests/e2e/lab/upload_window.mjs`，證據寫入 `~/.woowbk-lab/evidence/hardening/<時間>-<情境>/`（`driver.log`、
`result.json`、作業紀錄）。H1–H7 與 `sec1` 在 dev-a（需要設備金鑰）執行，H8 上傳到 dev-b；`fidelity` 用兩台，`fresh`
在 dev-b。每個情境結束時把設備恢復原狀（刪除測試備份、移除注入的錯誤與探測檔、卸載 tmpfs）；`fidelity` 與 `fresh` 會先把
dev-b 重設為全新目標，`fresh` 結束時 dev-b 和 cli_e2e s2 之後一樣：示範應用已部署並執行。

| 指令 | 內容 |
| --- | --- |
| `h1` | F5：在 dev-a **設備內**用設備金鑰解開一份新的基礎備份，注入一種缺陷後以設備公鑰重新加密（主機只拿到密文），經真正的 bridge 上傳 → upload-finish → inspect → verify 作業 → 原位還原作業。28 種加 1 個對照組：路徑穿越／絕對路徑／PAX path 覆寫、符號連結／硬連結／裝置／目錄成員、多出／缺少／重複／順序錯亂、大小謊報（大、小）、校驗值錯誤、結尾多餘資料、manifest 不在第一個、檔頭與 manifest 不符、manifest 中的穿越路徑／重複項目／指向其他應用、設定檔路徑不在 `.config/`／含 `..`／權限 0755、擁有者 root、manifest 超過 1 MiB、成員超過 4000、目錄中沒有的應用、目錄未宣告的設定檔／密鑰／資料卷／資料庫／Quadlet／映像（還原成功、全部被略過）。每種都檢查：拒絕原因（引擎驗證器的 `details.reason`）、staging 清空、沒有金鑰暫存檔、沒有孤兒封存檔、應用資料與部署檔不變，並用「變更檔案掃描」（自我測試會先證明它能抓到 /etc、/home、資料目錄與資料卷內的寫入）確認沒有寫到 staging 以外 |
| `h2` | F6：在設備內把 600 MiB 的 tmpfs 掛在 `/var/lib/woowtech-backup` 上（原資料仍在底下，卸載即恢復）：含映像備份在「檢查」階段以 `insufficient-space` 失敗、寫入服務未暫停、`/healthz` 全程 200；142 MB 上傳在 upload-begin 被拒，`可用−512 MiB` 邊界上下 1 MiB 各測一次；不含映像的備份可放入（對照） |
| `h3` | F7：替換資料庫容器內的 `pg_dump`（容器重建即消失，結束時一定還原）：失敗並輸出一半、結束碼 0 但少了結尾 64 bytes、結束碼 0 但只有一半、執行中資料庫被關閉。檢查失敗階段為「匯出資料庫」、寫入服務已恢復、沒有列出備份、staging 清空；「被截斷但結束碼 0」的備份若被接受，必須真的能還原 |
| `h4` | 在設備內用監看程式讀作業紀錄，於 `stop`／`dump`（以慢速 pg_dump 撐住）／`export`／`package`／`verify` 階段 `systemctl kill --signal=SIGKILL`；在呼叫 helper 之前先記錄應用狀態，證明是復原流程重新啟動寫入服務；檢查 interrupted＋指引、staging 移除、沒有孤兒封存檔、下一次備份成功 |
| `h5` | 還原進入 `start` 階段（資料卷已刪除）時 `labpodman restart woowbk-dev-a`；開機後作業為 interrupted＋還原前備份 ID，還原該備份後資料等於還原前（完整內容） |
| `h6` | 資料卷寫入約 600 MiB 亂數檔：不含映像的備份、bridge 下載、原位還原；主機端讀取設備 cgroup 的 `memory.peak`（每個 fd 可歸零）與每 0.25 秒的 `memory.stat`，回報包含 page cache 的峰值與 anon＋kernel＋shmem 峰值、OOM 計數；最後刪除大檔與大型備份 |
| `h7` | `/opt/woow-cockpit-src` 的 `manage.py plan/install/verify` → 回退最新交易 → 繼續回退到備份套件被移除（helper、頁面、目錄設定都不在）→ 重新安裝；每一步比對 `/var/lib/woowtech-backup` 與金鑰目錄的內容雜湊 |
| `sec1` | 審查發現 SEC-1 的實機版：先做對照組，證明設備上真正的 podman 4.9.3 會照做（appowner 以裸 `podman volume import` 與 `podman load` 匯入「絕對路徑符號連結＋其下的成員」的 tar，成員確實被寫進家目錄中的標記目錄，之後刪除）。接著在 dev-a **設備內**用設備金鑰解開一份新的含映像備份（串流到 `/var/tmp/woowbk-sec1-work`，明文在離開前刪除），在資料卷 tar 與應用映像的 OCI 封存**所有真實成員之後**各加上指向 `~/.config/systemd/user`、`~/.config/containers` 的絕對符號連結與其下的成員，修正 manifest 的大小與 sha256，以設備公鑰重新加密（主機只拿到密文）；並以已安裝引擎的 `nested` 檢查記錄原始項目通過、改造項目被拒的原因。經真正的 bridge 上傳 → upload-finish → inspect → 驗證作業 → 原位還原作業：還原必須在 preflight 失敗（safety、stop 未執行），錯誤分別點名容器映像與資料卷；期間 appowner 的 podman 沒有任何 image／volume 事件（沒有 load、tag、volume create/remove/import）、變更檔案掃描乾淨、整台設備找不到 `woowbk-sec1` 路徑、家目錄設定與應用資料、部署檔、映像名稱不變、沒有還原前備份。驗證作業只檢查外層封存，會回報完整（記為觀察） |
| `fidelity` | 合法資料的保真度：在 dev-a 應用資料卷的 `woowbk-fidelity/`（應用不計數）以 `podman unshare` 建立絕對／相對／懸空符號連結、硬連結、超過 100 bytes 的名稱與超過 255 bytes 的路徑、空目錄、setgid 與 sticky 目錄、user.* 延伸屬性、非 UTF-8 檔名、中文檔名、FIFO、不同擁有者（70、1000、33、54999）、唯讀與可執行檔、次秒 mtime；以**應用容器內**（`podman exec`）看到的完整清單（類型、容器內 uid/gid、權限、大小、mtime、連結目標、sha256、延伸屬性、硬連結群組）為準。含映像備份 → 修改探測目錄 → 原位還原 → 清單必須相同；再下載 → dev-b 重設 → 上傳 → 全新部署還原（緊急金鑰）→ dev-b 容器內清單必須相同（只有次秒 mtime 因 tar 只存整秒而不同）。結束時刪除探測目錄與測試備份 |
| `fresh` | dev-b 全新部署還原：(1) 預先存在同名的應用機密、設定檔、資料卷或資料庫資料卷（各自單獨測）→ inspect 與還原作業都在 preflight 拒絕，什麼都沒有刪除或建立；(2) 另建無關的資料卷、機密、設定檔、網路與映像名稱，並讓 `localhost/woowbk-demo-app:1` 先指向探測映像；還原在 `start` 階段被 SIGKILL（範本、遮蔽、機密、設定檔、資料卷都已建立）→ 復原移除整個部署、無關物件不變；已載入的映像名稱照 CONTRACT §8 保留；(3) 以一次性的資料庫 drop-in 讓還原在破壞性步驟後失敗 → 程序內自動回復 → `remove_fresh` 把映像名稱改回原本的探測映像（retag），或移除這次新增的名稱（untag），無關物件不變。最後再做一次全新部署還原，資料等於來源備份 |
| `leaks` | 兩台設備的作業紀錄、日誌、索引、requests、journal 沒有應用密鑰或 age 金鑰；沒有 `key-*`、staging、孤兒封存檔；主機 hardening／integration 證據沒有金鑰 |
| `upload_window.mjs [MiB=2,4] [次數=3] [chunkKiB=64,256,512]` | H8：以 Playwright 攔截 `backup.js`，只在測試瀏覽器內改 `WINDOW_SIZE` 與 `CHUNK_SIZE` 並加上計時；經 cockpit-ws 上傳約 142 MB 到 dev-b，核對 sha256，停在金鑰步驟後刪除。程式庫與設備上的預設值（4 MiB 視窗、512 KiB 訊框）不變 |

`H1_CASES`、`H3_FAULTS`、`H4_KILLS`、`H5_PHASE`、`H6_FILES`、`H7_FULL=0`、`H2_TMPFS` 環境變數可只跑一部分。

## 作業紀錄競態探測（race probe）

`python3 -I tests/e2e/lab/race_probe.py <a|b> [--jobs 110] [--pollers 3] [--settle 0.5] [--census-only]`，
證據寫入 `~/.woowbk-lab/evidence/race/<時間>-probe-<設備>/`（`driver.log`、`result.json`、`probe-summary.json`、
`census-before.json`、`census-after.json`）。在設備內以 root、和頁面相同的方式呼叫已安裝的 helper：連續執行 N 個最小
本機備份的驗證作業，同時有 P 個執行緒不停呼叫目前作業的 `job-status`，另有一個呼叫 `jobs`、一個呼叫 `status`
（三者都會執行中斷復原）；作業結束後 pollers 再持續 `--settle` 秒，這正是舊版復原把剛結束的作業誤判為「已中斷」的視窗
（發布回歸 16）。作業紀錄的狀態必須等於作業自己寫下的結果（日誌中的 `作業結束：…`），不能出現
`作業被判定為已中斷`，任何 poller 也不能看到 `interrupted`。為了證明探測真的落在競態視窗內，另外統計「作業寫入最後紀錄
（紀錄檔 mtime）的那一刻，仍在執行中的 `job-status`／`jobs`／`status` 呼叫數」，沒有任何重疊時判定探測無效（失敗）。同時檢查保留策略（已結束的紀錄最多 200 筆，加上進行中、
仍需復原處理與釘選還原前備份的紀錄；日誌與鎖檔不會比紀錄多；釘選的還原前備份前後相同）、每種 helper 呼叫的延遲、
`/run/woowtech-backup` 的暫時金鑰與 staging。dev-a 驗證自己的最小備份（應全部成功）；dev-b 沒有那份上傳備份的金鑰，
驗證作業會以 `key-required` 結束（全部「失敗」，同樣是作業自己寫下的結果），不需要傳送任何金鑰。
`--census-only` 只用已安裝的程式庫唯讀統計紀錄，不呼叫 helper（不會觸發復原或保留策略）。

## 已實測的事實與注意事項

* **巢狀儲存**：appowner 的儲存在 `/home` 資料卷（主機 ext4），`podman info` 為 `overlay`、
  `Native Overlay Diff: true`、`Backing Filesystem: extfs`，不需要 fuse-overlayfs（仍已安裝並傳入 `/dev/fuse`）。
* **subuid/subgid**：`appowner:10000:55000`。設備容器本身只對應 65536 個 ID（0–65535），useradd 預設的
  `100000:65536` 在設備內無效，`woowbk-provision` 會改寫兩個檔案。巢狀容器對應為 `0→<appowner uid>`、
  `1..55000→10000..64999`，避開真實帳號（0–9999）與 nobody（65534）。映像中若有 UID > 55000 的檔案無法使用。
* **cgroup**：v2，systemd 管理；`cpu memory pids` 委派到 `user@<uid>.service`，巢狀容器的 `--memory` 有效
  （實測 alpine `memory.max=67108864`）。示範應用的 Quadlet 以 `PodmanArgs=--memory` 限制 256m／128m。
* **網路**：rootless 巢狀容器用 netavark＋aardvark-dns（名稱解析）＋slirp4netns，可連外網拉取映像；
  `woowbk-demo` 網路為 `10.89.0.0/24`（`podman1`）。發佈在設備 127.0.0.1 的埠（例如 18090）可由設備內 root 存取。
* **systemd**：容器內 systemd 不會把 `/` 設為 shared，rootless podman 每個指令都會警告；映像內的
  `woowbk-rshared.service` 在開機時執行 `mount --make-rshared /`。`proc-sys-fs-binfmt_misc.automount`
  在容器內必定失敗，已遮蔽；遮蔽後 `systemctl is-system-running` 為 `running`。
* **記憶體顯示**：設備內 `free` 與 Cockpit 總覽顯示的是主機記憶體（沒有 LXCFS）；實際上限是
  `/sys/fs/cgroup/memory.max`（768 MiB）。實測 dev-a（PostgreSQL＋應用＋Cockpit）約 85 MiB，dev-b 約 55 MiB。
* **重新開機**：`down.sh` 約 2 秒（SIGRTMIN+3），`up.sh` 後 linger 讓 appowner 的 user manager 與
  示範應用自動啟動，資料與摘要不變；machine-id 只有在重建容器時才改變。
* **Cockpit**：登入頁標題為主機名稱；`superuser` 開啟後右上角顯示「Administrative access」。在 Playwright
  的 `frame.evaluate` 中，`cockpit.spawn()` 回傳的是 Cockpit 自己的 thenable，需包在 `async` 函式中 `await`。
* Ubuntu 套件會啟用 rootful 的 `podman.socket`／`podman-restart.service` 等單元；保留預設，對測試無影響。
* **tmpfs**：設備內 root 可以 `mount -t tmpfs`（rootless `--privileged`）；掛在資料目錄上時 helper、systemd 作業與
  cockpit-bridge 都看得到。tmpfs 用量算在設備的記憶體上限內。
* **記憶體峰值**：設備內寫 `memory.peak` 會 EPERM；主機端（`labpodman inspect --format '{{.State.CgroupPath}}'`）
  可對同一個 fd 寫入以歸零並讀取該區間的峰值。page cache 會把用量推到 768 MiB 上限（`memory.events` 的 `max` 增加），
  判斷是否危險要看 anon＋kernel＋shmem 與 `oom_kill`。
* **journal**：設備的 `/var/log/journal` 是 tmpfs（podman `--systemd=always`），`labpodman restart` 後舊紀錄消失。
* **labpodman restart**：約 1 秒，3–4 秒後 systemd、appowner 的 user manager 與 cockpit.socket 就緒，linger 會自動啟動示範應用。
* **共用實驗室**：其他測試者可能同時在 dev-a 以 appowner 建立／刪除 `woowbk-sec-probe-*` 資料卷或映像（journal 可見）；
  `hardening.py` 的變更檔案掃描因此只容許 podman 自身狀態與目錄 mtime，並記錄視窗內的這類事件數。
* `podman secret inspect --showsecret --format {{.SecretData}}` 輸出原始值加一個結尾換行。
* **f8 的故障注入（2026-11-13 修正後）**：原本以「尚未套用的設定檔標題」讓還原後的資料核對不一致，但那正是審查發現
  CR-04 的快照競態；修正後這種備份不再帶資料核對快照，還原會成功。現在改為對資料庫的 Quadlet 單元暫時加一個
  drop-in（`~/.config/systemd/user/woowbk-demo-db.service.d/woowbk-f8.conf`，`ExecStartPost=` 只失敗一次並刪除標記檔），
  使還原時的資料庫啟動失敗、自動回復時的啟動成功；`finally` 一定移除 drop-in 並 `daemon-reload`。
* **還原期間的遮蔽**：原位與全新部署還原會在第一個破壞性步驟後以 `systemctl --user mask` 暫時停用應用的非資料庫單元
  （`~/.config/systemd/user/<unit> -> /dev/null`，優先於 Quadlet 產生器），完成或回復後才 `unmask`；作業中斷時
  總覽會把應用顯示為「異常」並說明需要再次還原。已在 dev-a 實測：`LoadState=masked`、`start` 被拒（結束碼 1）、
  `unmask` 後恢復。
