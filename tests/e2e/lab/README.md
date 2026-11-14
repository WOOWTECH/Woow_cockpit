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
| appowner subuid／subgid | `10000:55000`（預設） | `10500:55000`（`subids.sh` 設定，與 dev-a 刻意不同） |
| machine-id | 每台不同（首次開機由 podman 的 `container_uuid` 產生；重建容器會改變） | 同左 |
| 管理員 | `devadmin`（UID 1000，sudo 群組，Cockpit 登入，密碼見下） | 同左 |
| 資源上限 | `--memory 768m --cpus 1.5` | 同左 |
| 資料卷 | `woowbk-dev-a-home`→`/home`、`-varlib`→`/var/lib/woowtech-backup`（0700）、`-containers`→`/var/lib/containers` | `woowbk-dev-b-…` |
| 預設狀態 | 已部署並植入 woowbk-demo 與 woowbk-dirs（執行中） | 只有 appowner，**未部署**應用（跨設備還原目標；可能留有 postgres、python 基礎映像） |

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
| `deploy-dirs.sh <a\|b> [--items N] [--delete K] [--title T] [--owner-note T] [--seed S] [--no-seed]` | 同上，部署主機資料夾示範應用 woowbk-dirs（`catalog-examples/woowbk-dirs/README.md`）：複製到 `/opt/woowbk-dirs`、拉取 postgres（已有則略過）、建置 `localhost/woowbk-dirs-app:1`、安裝 Quadlet、seed（密鑰、設定檔、主機資料夾與容器帳號擁有者、資料庫角色與第二個資料庫、項目） |
| `dirs-catalog.sh <a\|b> install\|remove\|status` | 以 root 安裝或移除 woowbk-dirs 的受信任目錄項目（`/etc/woowtech-cockpit/backup/apps/woowbk-dirs.json`）與 Quadlet 範本，並列出已安裝引擎對它的判斷（沒有主機資料夾支援的引擎回報「不支援的欄位：data_dirs」並略過此應用） |
| `teardown-dirs.sh <a\|b> [--keep-image]` | 以擁有者身分移除整個 woowbk-dirs 部署（停止並解除遮蔽服務、測試 drop-in、Quadlet、容器、密鑰、網路、設定檔、兩個主機資料夾與其 `.woowbk-new-*`／`.woowbk-old-*`、應用映像），列出剩下的東西（必須是空的）；備份與目錄項目不動 |
| `subids.sh <a\|b> [START:COUNT --reset-storage]` | 顯示 appowner 的 subuid／subgid 與實際 `uid_map`；給範圍時先拆除兩個示範應用、確認家目錄沒有其他 ID 的檔案，再以舊對應 `podman system reset`、改寫 `/etc/subuid`／`/etc/subgid`、`podman system migrate` 並核對新對應（之後映像要重新取得或由備份還原）。`woowbk-provision` 會保留設備上有效的範圍 |
| `verify-device.sh <a\|b> [--no-browser]` | 實測：systemd `running`、Cockpit socket、user manager、巢狀 podman（alpine、uid map 等於設備 `/etc/subuid` 的範圍、`--memory`）、Quadlet 產生器、Playwright 登入並開啟管理員存取 |
| `cockpit-login.mjs <a\|b>` | Playwright：HTTPS 登入 devadmin → 開啟管理員存取 → `cockpit.spawn(['id','-u'], {superuser:'require'})` 必須為 0；截圖存於 `~/.woowbk-lab/evidence/lab/`（只在未輸入密碼或密碼欄消失後截圖） |
| `status.sh` | 兩台設備的狀態、systemd、記憶體、subuid 範圍、兩個示範應用的 `/healthz`（`demo-healthz` 18090、`dirs-healthz` 18091；000 為未部署或停止） |

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
| `h1` | F5：在 dev-a **設備內**用設備金鑰解開一份新的基礎備份（2026-11-13 起是格式 2 `.tar`：解開該應用的封存檔，注入缺陷後重新封裝成 `backup.json`＋README＋應用封存檔；`backup.json` 依注入前的應用內容產生，所以被判斷的是經過驗證的清單；格式 1 的基礎備份仍產生格式 1），注入一種缺陷後以設備公鑰重新加密（主機只拿到密文），經真正的 bridge 上傳 → upload-finish → inspect → verify 作業 → 原位還原作業。28 種加 1 個對照組：路徑穿越／絕對路徑／PAX path 覆寫、符號連結／硬連結／裝置／目錄成員、多出／缺少／重複／順序錯亂、大小謊報（大、小）、校驗值錯誤、結尾多餘資料、manifest 不在第一個、檔頭與 manifest 不符、manifest 中的穿越路徑／重複項目／指向其他應用、設定檔路徑不在 `.config/`／含 `..`／權限 0755、擁有者 root、manifest 超過 1 MiB、成員超過 4000、目錄中沒有的應用、目錄未宣告的設定檔／密鑰／資料卷／資料庫／Quadlet／映像（還原成功、全部被略過）。每種都檢查：拒絕原因（引擎驗證器的 `details.reason`）、staging 清空、沒有金鑰暫存檔、沒有孤兒封存檔、應用資料與部署檔不變，並用「變更檔案掃描」（自我測試會先證明它能抓到 /etc、/home、資料目錄與資料卷內的寫入）確認沒有寫到 staging 以外 |
| `h2` | F6：在設備內把 600 MiB 的 tmpfs 掛在 `/var/lib/woowtech-backup` 上（原資料仍在底下，卸載即恢復）：含映像備份在「檢查」階段以 `insufficient-space` 失敗、寫入服務未暫停、`/healthz` 全程 200；142 MB 上傳在 upload-begin 被拒，`可用−512 MiB` 邊界上下 1 MiB 各測一次；不含映像的備份可放入（對照） |
| `h3` | F7：替換資料庫容器內的 `pg_dump`（容器重建即消失，結束時一定還原）：失敗並輸出一半、結束碼 0 但少了結尾 64 bytes、結束碼 0 但只有一半、執行中資料庫被關閉。檢查失敗階段為「匯出資料庫」、寫入服務已恢復、沒有列出備份、staging 清空；「被截斷但結束碼 0」的備份若被接受，必須真的能還原 |
| `h4` | 在設備內用監看程式讀作業紀錄，於 `stop`／`dump`（以慢速 pg_dump 撐住）／`export`／`package`／`verify` 階段 `systemctl kill --signal=SIGKILL`；在呼叫 helper 之前先記錄應用狀態，證明是復原流程重新啟動寫入服務；檢查 interrupted＋指引、staging 移除、沒有孤兒封存檔、下一次備份成功 |
| `h5` | 還原進入 `start` 階段（資料卷已刪除）時 `labpodman restart woowbk-dev-a`；開機後作業為 interrupted＋還原前備份 ID，還原該備份後資料等於還原前（完整內容） |
| `h6` | 資料卷寫入約 600 MiB 亂數檔：不含映像的備份、bridge 下載、原位還原；主機端讀取設備 cgroup 的 `memory.peak`（每個 fd 可歸零）與每 0.25 秒的 `memory.stat`，回報包含 page cache 的峰值與 anon＋kernel＋shmem 峰值、OOM 計數；最後刪除大檔與大型備份 |
| `h7` | `/opt/woow-cockpit-src` 的 `manage.py plan/install/verify` → 回退最新交易 → 繼續回退到備份套件被移除（helper、頁面、目錄設定都不在）→ 重新安裝；每一步比對 `/var/lib/woowtech-backup` 與金鑰目錄的內容雜湊 |
| `sec1` | 審查發現 SEC-1 的實機版：先做對照組，證明設備上真正的 podman 4.9.3 會照做（appowner 以裸 `podman volume import` 與 `podman load` 匯入「絕對路徑符號連結＋其下的成員」的 tar，成員確實被寫進家目錄中的標記目錄，之後刪除）。接著在 dev-a **設備內**用設備金鑰解開一份新的含映像備份（串流到 `/var/tmp/woowbk-sec1-work`，明文在離開前刪除），在資料卷 tar 與應用映像的 OCI 封存**所有真實成員之後**各加上指向 `~/.config/systemd/user`、`~/.config/containers` 的絕對符號連結與其下的成員，修正 manifest 的大小與 sha256，以設備公鑰重新加密（主機只拿到密文）；並以已安裝引擎的 `nested` 檢查記錄原始項目通過、改造項目被拒的原因。經真正的 bridge 上傳 → upload-finish → inspect → 驗證作業 → 原位還原作業：還原必須在 preflight 失敗（safety、stop 未執行），錯誤分別點名容器映像與資料卷；期間 appowner 的 podman 沒有任何 image／volume 事件（沒有 load、tag、volume create/remove/import）、變更檔案掃描乾淨、整台設備找不到 `woowbk-sec1` 路徑、家目錄設定與應用資料、部署檔、映像名稱不變、沒有還原前備份。2026-11-13 起深入驗證作業以 `corrupt-archive` 拒絕，索引記錄 `verified {ok: false, deep: true}`（先前只檢查外層封存、回報完整）；格式 2 的基礎備份以已安裝引擎的 `ArchiveWriter` 重新封裝 |
| `fidelity` | 合法資料的保真度：在 dev-a 應用資料卷的 `woowbk-fidelity/`（應用不計數）以 `podman unshare` 建立絕對／相對／懸空符號連結、硬連結、超過 100 bytes 的名稱與超過 255 bytes 的路徑、空目錄、setgid 與 sticky 目錄、user.* 延伸屬性、非 UTF-8 檔名、中文檔名、FIFO、不同擁有者（70、1000、33、54999）、唯讀與可執行檔、次秒 mtime；以**應用容器內**（`podman exec`）看到的完整清單（類型、容器內 uid/gid、權限、大小、mtime、連結目標、sha256、延伸屬性、硬連結群組）為準。含映像備份 → 修改探測目錄 → 原位還原 → 清單必須相同；再下載 → dev-b 重設 → 上傳 → 全新部署還原（緊急金鑰）→ dev-b 容器內清單必須相同（只有次秒 mtime 因 tar 只存整秒而不同）。結束時刪除探測目錄與測試備份 |
| `fresh` | dev-b 全新部署還原：(1) 預先存在同名的應用機密、設定檔、資料卷或資料庫資料卷（各自單獨測）→ inspect 與還原作業都在 preflight 拒絕，什麼都沒有刪除或建立；(2) 另建無關的資料卷、機密、設定檔、網路與映像名稱，並讓 `localhost/woowbk-demo-app:1` 先指向探測映像；還原在 `start` 階段被 SIGKILL（範本、遮蔽、機密、設定檔、資料卷都已建立）→ 復原移除整個部署、無關物件不變；已載入的映像名稱照 CONTRACT §8 保留；(3) 以一次性的資料庫 drop-in 讓還原在破壞性步驟後失敗 → 程序內自動回復 → `remove_fresh` 把映像名稱改回原本的探測映像（retag），或移除這次新增的名稱（untag），無關物件不變。最後再做一次全新部署還原，資料等於來源備份 |
| `leaks` | 兩台設備的作業紀錄、日誌、索引、requests、journal 沒有應用密鑰或 age 金鑰；沒有 `key-*`、staging、孤兒封存檔；主機 hardening／integration 證據沒有金鑰 |
| `upload_window.mjs [MiB=2,4] [次數=3] [chunkKiB=64,256,512]` | H8：以 Playwright 攔截 `backup.js`，只在測試瀏覽器內改 `WINDOW_SIZE` 與 `CHUNK_SIZE` 並加上計時；經 cockpit-ws 上傳約 142 MB 到 dev-b，核對 sha256，停在金鑰步驟後刪除。程式庫與設備上的預設值（4 MiB 視窗、512 KiB 訊框）不變 |

`H1_CASES`、`H3_FAULTS`、`H4_KILLS`、`H5_PHASE`、`H6_FILES`、`H7_FULL=0`、`H2_TMPFS` 環境變數可只跑一部分。
格式 2 的 `unknown-app`：只讀被選應用的封存檔，還原 woowbk-demo 時在「解密並驗證檔案」就以 `incompatible` 拒絕（格式 1 在預檢）。`h7` 期待設備是 `deploy-src.sh` 剛安裝的狀態：若 woowbk-demo 的目錄項目已由「應用設定」（`catalog-install`）改過，`manage.py plan` 會列出它、回退也會拒絕（檔案在安裝後被變更）；`h7` 會先把 manage.py 管理的夾具內容放回，結束時再以 `catalog-install` 裝回管理者的版本。dev-a 的安裝交易紀錄中有一筆在 2026-11-13 被實驗室專用的 archive.py 修補改過（引擎核心角色的 E1–E3 暫時修補），所以完整回退鏈（`H7_FULL=1`）會在那一筆被 `manage.py` 正確拒絕（「Changed since installation」）；2026-11-14 整合輪以 `H7_FULL=0` 在一組乾淨的交易（先部署舊版再部署工作樹）上驗證。

## 主機資料夾情境（dirs_e2e.py，D1–D6）

`python3 -I tests/e2e/lab/dirs_e2e.py <prep|selftest|d1|d2|d3|d4|d5|d6|leaks|all>`，證據寫入
`~/.woowbk-lab/evidence/dirs/<時間>-<情境>/`（`driver.log`、`result.json`、作業紀錄），跨情境的狀態（來源備份 ID、
下載檔、備份時的快照）在 `~/.woowbk-lab/evidence/dirs/state.json`。呼叫方式與 `cli_e2e.py` 相同（已安裝的 helper、
root、stdin JSON；下載／上傳走設備內真正的 `cockpit-bridge`）。夾具是 `catalog-examples/woowbk-dirs`：PostgreSQL 16
的資料目錄是主機資料夾（容器內 UID 70，冷備份：不列 `postgres`、資料庫服務也在 `writer_units`），應用以容器內 UID 33
寫入另一個主機資料夾（巢狀資料夾、符號連結、硬連結、`user.*` 延伸屬性、WAL 模式的 SQLite、中文與空白檔名、0444
檔案、空資料夾）。比對以應用的 `/api/summary`（9 個值）之外，另比對完整的資料夾清單（`app/treelist.py`：類型、容器內
擁有者、權限、大小、sha256、整秒修改時間、連結目標、延伸屬性、硬連結）、兩個資料庫的資料列與角色／擁有者／叢集識別碼，
以及 SQLite 的資料列；清單在擁有者的使用者命名空間內讀取（`podman unshare`），應用停止或被遮蔽時也能比對。

前置條件（`prep` 逐項檢查，缺目錄項目時自動執行 `dirs-catalog.sh <a|b> install`，dev-a 應用不健康時執行
`deploy-dirs.sh a`）：兩台設備執行中、主機可用記憶體 ≥ 1200 MB；**已安裝含主機資料夾支援的引擎**（`deploy-src.sh a`、
`deploy-src.sh b`）；dev-a 的 woowbk-dirs 健康且 `tools/check.py` 通過；dev-b 的 subuid／subgid 範圍與 dev-a 不同
（`subids.sh b 10500:55000 --reset-storage`）；dev-a 的設備金鑰與緊急金鑰檔 `~/.woowbk-lab/secrets/dev-a-kit.txt`
（`cli_e2e.py s1` 建立）。`all` 依序執行 `prep d1 d3 d4 d5 d6 d2 leaks`，`prep` 未通過就停止。

| 情境 | 內容 |
| --- | --- |
| `prep` | 前置條件（見上） |
| `selftest` | 不需要引擎的新功能：使用者命名空間清單等於應用的 `/api/tree`、主機上的擁有者依 `uid_map` 換算、D4 的狀態注入（在暫存資料夾）、D4 的整棵行程樹終止（替身 systemd 單元，其中 `podman unshare` 的子行程被 podman 移到使用者的 scope，`systemctl kill` 殺不到它）、D5 的惡意 tar 產生器對已安裝引擎的巢狀檢查（每一種都被拒絕、原始 tar 通過） |
| `d1` | dev-a 原位：植入 → 備份（不含映像；寫入服務含資料庫都停止，`/healthz` 期間中斷，`downtime_seconds` > 0）→ inspect（`data_dirs` 列出兩個路徑、沒有 pg_dump 資料庫、快照等於備份前）→ 變更所有種類的狀態（兩個資料庫的資料列、新角色與新資料庫、UID 33 檔案的權限／延伸屬性／符號連結／多一個檔案、刪除空資料夾、擁有者的檔案、SQLite、設定檔）→ 原位還原 → 摘要、完整清單、資料庫與 SQLite 等於備份時；容器內與主機上的擁有者；沒有 `.woowbk-*` 旁資料夾（舊內容在成功後刪除）；新角色與新資料庫消失；應用可寫入；還原前備份含兩個主機資料夾；同設備的 woowbk-demo 不受影響 |
| `d2` | 跨設備全新部署：dev-a 含映像備份 → bridge 下載 → dev-b 以 `teardown-dirs.sh` 拆除 → 上傳 → 無金鑰 `key-required` → 緊急金鑰 inspect（來源 UID 1001、預檢 fresh）→ 還原 → dev-b 的摘要、完整清單（含容器內 UID 0／33／70、權限、修改時間、延伸屬性、硬連結）、資料庫（含叢集識別碼與角色）與 SQLite 等於 dev-a 備份時；主機上的擁有者依 **dev-b** 的對應（33 → 10532、70 → 10569，與 dev-a 的 10032／10069 不同）；缺少的上層資料夾由擁有者（1007）建立；應用以還原的 `dirs_app` 密碼寫入新資料 |
| `d3` | 備份 → 變更 → 以一次性的 drop-in 讓資料庫服務在還原的 `start` 階段（資料夾已對調之後）啟動失敗 → 自動回復：狀態 `rolled-back`，資料（摘要、清單、資料庫、SQLite）等於**還原前**而非備份，服務已解除遮蔽；沒有 `.woowbk-new-*`，回復保留的 `.woowbk-old-*`（舊內容只在作業成功後刪除）必須寫在作業的注意事項或紀錄中，且資料夾的那一份等於還原前的內容（之後由測試刪除） |
| `d4` | 三種強制終止（整棵行程樹 SIGSTOP＋SIGKILL，再 `systemctl kill`，所以沒有任何 helper 能在之後完成改名）：`extract`（第一個 `.woowbk-new-*` 出現時，正在解開；2026-11-13 起主機資料夾在 `stage` 階段、還原前備份與任何停止之前就先寫入，所以這時應用仍在執行、還沒有還原前備份：作業 `interrupted`、應用照常執行、資料不變、新資料夾由復原移除，不還原還原前備份）、`between`（作業進入 `restore` 階段時終止（服務已停止並遮蔽、資料夾即將對調），再以擁有者身分把現場整理成「兩次改名之間」：`<路徑>` 不存在、`.woowbk-old-<作業>` 是原內容、`.woowbk-new-<作業>` 是新內容；改名之間只有微秒，無法可靠地在那一刻終止，所以用狀態注入）、`after-swap`（作業進入 `start` 階段時）。之後 `job-status` 觸發復原：作業 `interrupted` 並指出還原前備份、每個宣告的資料夾都存在、沒有 `.woowbk-new-*`、`between` 的原資料夾被移回（清單等於還原前）、整理過的資料夾都寫在作業訊息或紀錄中；保留的 `.woowbk-old-*` 必須有說明。最後還原還原前備份，資料等於終止前。`D4_CASES=extract,between` 可只跑一部分 |
| `d5` | 在 dev-a **設備內**以設備金鑰解開一份新的基礎備份（2026-11-13 起是格式 2 `.tar`：只解開該應用的封存檔，惡意案例以已安裝引擎的 `ArchiveWriter` 重新封裝成合法的 `backup.json`／README／每應用清單，只有資料夾 tar 是惡意的；格式 1 的基礎備份仍產生格式 1 案例），把 `woowbk-dirs/data` 的資料夾 tar 換成惡意版本（所有真實項目之後加上：絕對符號連結＋其下的檔案、離開資料夾的相對符號連結＋其下的檔案、絕對路徑、`..`、PAX path 覆寫、檔案之下的項目、指向資料夾外的硬連結、裝置檔、UID 60000（超出命名空間）、重複項目），修正 manifest 的大小與 sha256 後以設備公鑰重新加密（主機只拿到密文）。每一種都經 bridge 上傳 → 還原：必須在任何變更之前被拒絕（`incompatible`／`corrupt-archive`，安全備份與停止都沒有執行）、資料與兩個資料夾不變、找不到任何 `woowbk-d5-planted` 路徑、`~/.config/systemd/user` 與 `~/.config/containers` 不變。另有兩個授權規則案例：manifest 多列一個本機目錄沒有的資料夾（`woowbk-d5-planted-undeclared`、`.config/systemd/user`）→ 被拒絕，或還原成功但完全不寫入該路徑。`D5_CASES` 可只跑一部分 |
| `d6` | dev-b 全新部署目標上已存在**有內容**的 `woowbk-dirs/data`（另一次是 PostgreSQL 資料夾）→ inspect 的預檢不可還原並指出路徑、還原作業在預檢以 `incompatible` 失敗 → 資料夾內容、部署痕跡（Quadlet、密鑰、設定檔、另一個資料夾）都沒有變；已存在但**空的**資料夾只記錄預檢結果 |
| `leaks` | 兩台設備的作業紀錄、日誌、索引、requests、journal 沒有 woowbk-dirs 的三個密鑰或 age 金鑰；主機的 dirs 證據沒有金鑰 |

2026-11-13 已實測（引擎尚未支援主機資料夾，設備上是 2026.11.12.4）：`selftest` 21/21 通過；`prep` 16/18，未通過的
兩項就是「已安裝引擎不支援 `data_dirs`」，跑完後已以 `dirs-catalog.sh a|b remove` 移除目錄項目，其他測試者的狀態頁不會多出
提示。d1–d6 與 `leaks` 需要新引擎，由整合者在 `deploy-src.sh a`、`deploy-src.sh b` 之後執行。

## 備份格式 2 與加密選擇（format_e2e.py，S4–S6、F13–F15）

`python3 -I tests/e2e/lab/format_e2e.py <v1|encrypted|plain|export|deep|partial|cleanup|all>`，證據寫入
`~/.woowbk-lab/evidence/format/<時間>-<情境>/`，建立的備份（含其還原前備份）記在同目錄的 `state.json`，由 `cleanup`
刪除。前置條件：兩台設備已 `deploy-src.sh a|b`、woowbk-demo 在兩台都執行中、woowbk-dirs 在 dev-a 執行中（`partial`）、
dev-a 的緊急金鑰檔（實驗室拋棄式）在 `~/.woowbk-lab/secrets/dev-a-kit.txt`。主機上解開的明文只放在
`~/.woowbk-lab/run/format/` 的 0700 資料夾，情境結束前刪除。

| 情境 | 內容 |
| --- | --- |
| `v1` | F15：dev-a 上既有的格式 1（`.woowbackup`）woowbk-demo 備份仍可 inspect、深入驗證（結果 `format` 1、`verified.deep`）並原位還原，資料等於備份時；沒有舊備份時略過 |
| `encrypted` | S4：預設加密的格式 2 備份（索引 `format` 2、每應用封存檔大小）→ bridge 下載 → 主機 GNU tar 列出 `backup.json`、`README.txt`、`apps/woowbk-demo.tar.zst.age`；`backup.json` 沒有公鑰或私鑰文字；**照 README 的指令**以緊急金鑰 `age -d | zstd -d | tar -x` 解開，每個項目的大小與 sha256 等於清單 → 深入驗證作業（資料卷、資料庫匯出、應用機密都檢查過）→ 上傳到 dev-b（保留檔名、未持有金鑰）→ 以緊急金鑰 inspect 與還原 → dev-b 資料等於 dev-a 備份時 |
| `plain` | S5：設定開啟時 `encrypt:false` 沒有 `acknowledge_plaintext` 被拒 → 確認後建立未加密備份（`key_id` null、不需金鑰）→ 主機只用 `tar -xzf` 解開並核對 → 原位還原（還原前備份依設定加密）→ 上傳 dev-b：`unauthenticated`、預檢警告、沒有 `accept_unauthenticated` 的還原被拒、有則成功 → 關閉「預設加密備份」（需確認，settings.json root 0644）後備份與還原前備份都不加密 → 設定改回；journal 記錄兩次設定變更 |
| `export` | S6：沒有 `confirm` 的 export-start 被拒 → 未加密副本作業四個階段完成 → `export-info` 的路徑在 `exports/`、`-unencrypted.tar`、約 15 分鐘後到期；`exports/` root 0700、副本 root 0600；有暫時計時器 → 下載並以 `tar -xzf` 解開核對 → 模擬到期後由計時器的 `export-cleanup` 刪除；第二份由下一次 `status` 刪除 → journal 有 request／created／download／deleted |
| `deep` | F13：在設備內把一份新備份的資料卷 tar 加上離開資料卷的符號連結，以設備公鑰重新封裝（sha256 都正確）→ 上傳成功 → 深入驗證作業以 `corrupt-archive`（資料卷）失敗、索引 `verified {ok:false, deep:true}` → 還原在任何變更之前被拒、資料不變 |
| `partial` | F14：woowbk-demo＋woowbk-dirs 兩應用備份 → 在設備內破壞 `apps/woowbk-dirs.tar.zst.age` 中間一個位元組 → 只還原 woowbk-demo 成功、資料等於備份 → 驗證作業找到另一個應用的損壞 → 還原 woowbk-dirs 在任何變更之前失敗、應用仍執行 |
| `cleanup` | 刪除各情境建立的備份與還原前備份、未加密副本，確認設定為加密、沒有進行中的作業、staging 為空 |

## 強化階段整合情境（strengthen_e2e.py、strengthen_ui.mjs，整合者）

`python3 -I tests/e2e/lab/strengthen_e2e.py <情境…|all>` 與 `node tests/e2e/lab/strengthen_ui.mjs <部分…>`，證據寫入
`~/.woowbk-lab/evidence/strengthen/<時間>-<情境>/`。呼叫方式與 `cli_e2e.py` 相同（已安裝的 helper、root、stdin JSON；
下載／上傳走設備內真正的 `cockpit-bridge`）；頁面部分以 Playwright 操作真正的 Cockpit 362。建立的備份記在同目錄的
`state.json`（頁面：`ui-state.json`），由 `cleanup`（頁面：`cleanup-lab`）刪除。前置條件：兩台設備已 `deploy-src.sh a|b`、
woowbk-demo 與 woowbk-dirs 在兩台都執行中、dev-a 的緊急金鑰檔。惡意或損毀的封存檔都在 dev-a **設備內**以設備金鑰重新封裝
（主機只拿到密文）；巢狀容器一律帶 `--memory`。

| 情境 | 內容 |
| --- | --- |
| `catalog-apply` | 兩台設備：`catalog-suggest {}` 列出 appowner → 兩個示範應用的草稿（已安裝的設定＋產生器附加的 `postgres-digest`／`files-digest`，`installed.changes` 只有這兩項、沒有 drift）→ `catalog-install` 預覽（引擎驗證）→ 以預覽的 `expected_sha256` 確認安裝 → 檔案 root 0644、舊設定在 `apps-history`；兩台設備的設定完全相同。重新部署（`deploy-src.sh` 會把 woowbk-demo 換回夾具）後其他情境會自動補裝 |
| `digests` | woowbk-demo（單一資料庫）與 woowbk-dirs（主機資料夾中的冷備份資料庫）：備份時在寫入服務停止期間計算摘要 → inspect 列出摘要與統計 → 變更資料 → dev-a 原位還原：兩個摘要逐項一致、http-json 也一致、所有摘要比對都在應用單元啟動之前 → 下載、dev-b 拆除後上傳、以緊急金鑰全新部署還原（UID 1007、另一組 subuid）：摘要同樣一致 |
| `mismatch` | (a) 備份在設備內重新封裝，只把一個上傳檔案的內容改一個位元組（所有 sha256 都正確，深入驗證也通過）→ 原位還原：files-digest 指出該檔案「內容不同」、應用沒有在損毀的資料上啟動、自動回復、資料等於還原前；(b) 目錄不知道的容器，以及資料庫容器內的工作（類似 pg_cron，經本機 socket 寫入），在備份期間持續寫入資料庫 → 備份時兩次讀取的資料庫摘要不同，這份備份不保存資料庫摘要並在作業紀錄說明（2026-11-14 審查 H2/F3；以前會保存並讓每次還原都比對失敗）；(c) 它們仍在寫入時再還原 (a) 的備份：還原前備份也不保存資料庫摘要，還原因檔案摘要不同而自動回復並**完成**（`rolled-back`，應用沒有被暫時停用；以前回復時資料庫摘要不一致，應用停在暫時停用）；(d) 寫入的容器仍在時，還原一份沒有寫入者時建立的備份：資料庫摘要不一致時再讀一次，兩次不同就是資料仍在移動，這一項「未比對」並列入注意事項，還原完成（寫入者在兩次讀取之後才重新連上時，摘要直接一致）；寫入者移除後還原 (b) 的備份成功，資料庫摘要顯示「未比對」、檔案摘要一致。只用另一個容器寫入不夠穩定：應用容器停止後，它在共用的 Podman 網路上有幾秒連不上資料庫（實驗室 2026-11-14 第一次執行時因此兩次讀取相同） |
| `deep` | 以重新封裝（sha256 都正確）的備份檢查深入驗證：未修改的對照組通過且索引 `verified.deep`；資料卷離開資料卷的符號連結、主機資料夾的絕對符號連結與其下的檔案、與統計不符的摘要清單、不是 pg_dump 的資料庫匯出都讓驗證作業以 `corrupt-archive` 失敗並記錄 `{ok: false, deep: true}`；inspect（只讀清單）仍然很快且可以讀 |
| `instance` | 實驗室應用 `woowbk-inst`（`catalog-examples/woowbk-inst`：pgvector 映像、類 Nextcloud 的 `oc_admin`（應用用它登入，密碼只在應用資料卷）與 vector／pg_trgm、HNSW／GIN 索引，類 Odoo 的 `odoo` 角色擁有兩個資料庫）：以擁有者部署 → `catalog-suggest` 的「整個執行個體」變體＋範本位置與應用核對 → `catalog-install` 到兩台 → 備份（資料庫不停止）→ 破壞 → 原位還原與 dev-b 全新部署還原：角色與密碼雜湊、成員、設定、資料庫擁有者／定序／權限／註解、內容、擴充套件版本、索引都等於備份時，`odoo` 以原密碼登入、應用正常、摘要一致 |
| `keyless` | dev-b（沒有設備金鑰）：預設加密時建立備份 → `no-device-key`；`encrypt:false` 需要 `acknowledge_plaintext`；確認後建立未加密備份（`key_id` null、不是 unauthenticated）；設定開啟時原位還原需要金鑰（預檢 `device-key` 失敗、作業在任何變更前失敗）；關閉設定（需確認，settings.json root 0644）後不帶 `encrypt` 的備份不加密、原位還原成功且還原前備份也不加密；設定改回後加密備份仍需要金鑰；journal 記錄兩次設定變更 |
| `retention` | dev-b：保留最新 2 份 → 每次手動備份依原則刪除較舊的手動備份（不刪剛建立的那份）、journal 記錄；以 SIGKILL 中斷一次原位還原 → 還原前備份與該次還原的來源都列為受保護、`retention-apply` 略過並說明 → 還原還原前備份成功後不再受保護、可刪除；原則改回全部保留 |
| `tampered-json` | 下載的格式 2 備份：`backup.json` 的成員 sha256 被改 → `upload-finish` 拒絕；只改說明文字 → 上傳成功但 inspect、驗證作業、還原都以 `corrupt-archive` 拒絕（與經過驗證的各應用清單不符），資料不變；原檔仍可正常上傳 |
| `e4`、`e4-cleanup` | 停機量測：woowbk-dirs 加上兩個停止需 15 秒的寫入服務（模擬 n8n 的 task runners）與 300 MB 主機資料夾，以同一份資料比較目前安裝的引擎（`E4_LABEL`）；`E4_AFTER=1` 讓這兩個服務宣告 `After=` 應用（正式主機 n8n-runners 的寫法）。輸出寫入暫停、應用自己 `/healthz` 中斷的次數與時間（區分停止期間與其他時間） |
| `cleanup` | 刪除本驅動程式建立的備份、移除 woowbk-inst（部署、目錄項目、範本、pgvector 映像），設定與保留原則改回預設 |

`strengthen_ui.mjs` 的部分：`catalog`（dev-a「應用設定」：掃描 appowner、編輯器的 JSON 語法錯誤（行與字元位置，不送出）、
引擎拒絕 owner root 並指出欄位、預覽差異只多兩個摘要核對、勾選確認後安裝兩個應用、`apps-history` 與 journal）、`cleanup`
（dev-a「清理備份」：woowbk-demo 保留最新 5 份 → 預覽清單等於引擎的 `retention-plan`、可取消勾選（保留最新的 `.woowbackup`）
→ 確認刪除 → journal；再以「只儲存原則」改回全部保留）、`backups`（預設加密備份關閉與開啟、建立頁的加密選擇兩種、頁面下載
加密 `.tar` 後以 tar 讀 `backup.json`、照 README 指令以緊急金鑰解開並核對每個項目、未加密副本、深入驗證、原位還原結果的
資料核對表與停機時間）、`devb`（dev-b 沒有金鑰仍可建立未加密備份；關閉設定後經頁面上傳 dev-a 的未加密備份：預檢警告來源
無法驗證、確認步驟需要額外勾選、還原成功且摘要一致；設定改回）、`cleanup-lab`（刪除頁面建立的備份與未加密副本）。

### 資料摘要 SQL 探測（digest_sql_probe.py，2026-11-14 審查修正）

`python3 -I tests/e2e/lab/digest_sql_probe.py [證據目錄]`：以 labpodman 啟動一次性的 `postgres:16-alpine`（`--memory 384m`），
用引擎自己的 `woowbackup.digests` SQL（與 adapter 相同的 `psql -f -`、`PGOPTIONS`、`PGCLIENTENCODING=UTF8`）檢查：
非超級使用者的資料表擁有者定義 `CREATE CAST (victim AS text) WITH FUNCTION evil(victim)`（函式以 `COPY … TO PROGRAM`
寫一個標記檔）——修正前的 `t::text` 會以超級使用者身分執行它（標記檔內容 `postgres super=true`），引擎的 SQL 不會（H1）；
沒有自訂轉換、沒有 `t` 欄位的資料表，摘要與修正前完全相同；有名為 `t` 的欄位時，其他欄位改變摘要也會改變（F2）；
SQL_ASCII 資料庫中 0x80 以上的位元組、LATIN1 資料庫的非 ASCII 資料表名稱（與 UTF-8 資料庫的相同內容摘要相同；F6）。
結束時移除容器，結果寫入 `digest-sql-probe.json`。

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
* **subuid/subgid**：dev-a `appowner:10000:55000`，dev-b `appowner:10500:55000`（2026-11-13 以 `subids.sh` 設定，跨設備還原時容器帳號的檔案在兩台設備上的主機 ID 不同；`woowbk-provision` 保留它）。設備容器本身只對應 65536 個 ID（0–65535），useradd 預設的
  `100000:65536` 在設備內無效，`woowbk-provision` 會改寫兩個檔案。巢狀容器對應為 `0→<appowner uid>`、
  `1..55000→10000..64999`（dev-b：`10500..65499`），避開真實帳號（0–9999）與 nobody（65534）。映像中若有 UID > 55000 的檔案無法使用。
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
