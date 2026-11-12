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
| `python3 -I tests/e2e/lab/cli_e2e.py all` | 以頁面相同的方式呼叫**已安裝**的 helper（root、stdin JSON、單一 JSON 回應）；下載／上傳走設備內真正的 `cockpit-bridge`（`fsread1`、`fsreplace1`＋`send-acks`、64 KiB、≤ 2 MiB 未確認）。情境：`s1`（dev-a 金鑰、植入、含映像備份、F10 去重與 busy、變更、原位還原）、`s2`（先把 dev-b 重設為全新目標；A 下載 → B 上傳、key-required、F1 錯誤金鑰、緊急金鑰、全新部署還原、還原後可寫入）、`faults`（F2 截斷、F3 翻轉位元、F4 非備份檔與新版格式、驗證作業、F12 非 root）、`s3`（不含映像的備份在沒有本機映像的設備預檢失敗、不留任何東西）、`s2-again`、`f8`（破壞性步驟後失敗 → 自動回復，資料等於還原前）、`f9`（SIGKILL 還原 → interrupted、以還原前備份還原）、`leaks`（作業紀錄、日誌、索引、journal 沒有密鑰或金鑰）。dev-a 的緊急金鑰（實驗室拋棄式）存於 `~/.woowbk-lab/secrets/dev-a-kit.txt` |
| `node tests/e2e/lab/ui_e2e.mjs all` | 以 Playwright 登入真正的 Cockpit 362（devadmin），操作已安裝的「備份與還原」頁面：`admin`（受限存取 → 需要管理員權限；切換後載入真實資料，F12）、`s1`（頁面建立含映像備份、作業中關閉分頁再開啟會回到作業（F11）、經 cockpit-ws 外部 `fsread1` 通道下載並核對 SHA-256、從列表原位還原、結果表「資料一致」）、`s2`（dev-b 重設後由頁面上傳（websocket `fsreplace1`）、金鑰步驟、預檢 UID 1007、全新部署、可寫入）。需要 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 或 `~/.cache/ms-playwright/chromium-1248` |

重設 dev-b 只做擁有者層級的移除（停止服務、刪除 Quadlet、資料卷、密鑰、設定檔與示範應用映像）並刪除 dev-b 的備份，
不重建設備。

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
* `podman secret inspect --showsecret --format {{.SecretData}}` 輸出原始值加一個結尾換行。
