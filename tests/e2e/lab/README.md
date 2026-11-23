# 備份與還原實驗室設備（team L）

兩台彼此隔離、接近實機的 Ubuntu 24.04「設備」（dev-a、dev-b），供備份與還原端到端測試使用；第三台 dev-c 跑本主機
Odoo 與 n8n 的複本，供 HA 匯入測試（見「[dev-c：正式主機 Odoo 與 n8n 的複本](#dev-c正式主機-odoo-與-n8n-的複本ha-匯入測試)」）；第四台 dev-d 跑本主機
Omnigent、Hermes、EMQX 與 Headscale 的複本，供 HA 匯入第一批的測試（見「[dev-d](#dev-d正式主機-omnigenthermesemqx-與-headscale-的複本ha-匯入第一批)」）；第五台 dev-e 跑本主機
Nextcloud、code-server 與 OpenDesign 的複本，供 HA 匯入第二批，沒有網路也沒有發布連接埠（見「[dev-e](#dev-e正式主機-nextcloudcode-server-與-opendesign-的複本ha-匯入第二批)」）。每台設備是一個以
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
| `up.sh <a\|b\|c\|d>` | 建立或啟動設備，等到 systemd 開機完成、`cockpit.socket` 監聽 9090、`user@<uid>.service` 啟用且有 memory 控制器（沒有時重新啟動它一次；否則巢狀容器的 `--memory` 會以 `crun: opening file memory.max` 失敗）；設定 devadmin 密碼、appowner、subuid/subgid、linger。啟動前檢查主機可用記憶體 ≥ 1200 MB |
| `down.sh <a\|b\|c\|d\|all> [--rm]` | 停止設備（保留容器與資料卷）；`--rm` 另移除容器但保留資料卷 |
| `reset.sh <a\|b\|c\|d> [--up]` | 刪除設備**與其所有資料卷**（含巢狀映像、應用資料、備份）；`--up` 隨即重建 |
| `exec.sh <a\|b\|c\|d> [cmd…]` | 以 root 在設備內執行（預設互動 shell） |
| `owner.sh <a\|b\|c\|d> cmd…` | 以 appowner 執行，方式與引擎相同（`runuser -u appowner -- env -i … XDG_RUNTIME_DIR=/run/user/<uid> DBUS_SESSION_BUS_ADDRESS=…`） |
| `engine.sh <a\|b\|c\|d> <command> [json\|-]` | 以 root 呼叫 `/usr/local/libexec/woowtech-cockpit-backup`，輸出單一 JSON 並遮蔽 `key`／`content` 字串；帶金鑰的請求用 `-` 由標準輸入提供 |
| `deploy-src.sh <a\|b\|c\|d> [--src 工作樹] [--demo-catalog\|--no-demo-catalog] [--fallback]` | 把**目前工作樹**（或 `--src` 指定的 Woow_cockpit 工作樹；排除 `.git node_modules .local design __pycache__`）複製到設備 `/opt/woow-cockpit-src`（root 擁有、不可群組／其他人寫入），安裝程式支援時執行 `manage.py install --backup-demo-catalog`；`--no-demo-catalog`（dev-c 與 dev-d 的預設）只執行 `manage.py install`，不加 woowbk-demo 目錄項目；尚不支援時結束碼 3，`--fallback` 執行檔頭記載的實驗室專用手動安裝 |
| `deploy-prodlike.sh c --odoo-repo D --n8n-repo D [--cockpit-src D] [階段…]` | 只用於 dev-c：`packages images odoo n8n cockpit check`（見 dev-c 一節），每個階段都可以重跑 |
| `prodlike_baseline.py [odoo] [n8n]` | dev-c 的基準：每個應用一份加密備份與原位還原，前後的標記資料列證明資料真的還原（見 dev-c 一節） |
| `deploy-batch1.sh d --omnigent-repo D --hermes-repo D --emqx-repo D --headscale-repo D [--<應用>-rev R] [--cockpit-src D] [階段…]` | 只用於 dev-d：`packages images omnigent hermes emqx headscale cockpit check`（見 dev-d 一節），每個階段都可以重跑 |
| `batch1_baseline.py [omnigent] [hermes] [emqx] [headscale]` | dev-d 的基準：在每個應用放入標記資料（`batch1_markers.py`，在設備內以應用自己的 API、CLI 或程式碼建立與讀取），每個應用一份加密備份，再以原位還原證明它能還原（見 dev-d 一節） |
| `deploy-batch2.sh e [--nextcloud-repo D] [--code-server-repo D] [--opendesign-repo D] [--<應用>-rev R] [--cockpit-src D] 階段…` | 只用於 dev-e：`packages images[:應用] nextcloud code-server opendesign cockpit check[:應用] drop-images:應用 wake:應用 rotate:應用`（見 dev-e 一節），每個階段都可以重跑 |
| `batch2_baseline.py [nextcloud] [opendesign] [code-server]` | dev-e 的基準：標記資料（`batch2_markers.py`，在設備內以應用自己的介面建立與讀取）、每個應用一份加密備份，再以原位還原證明它能還原 |
| `batch2_baseline.py --verify [nextcloud] [opendesign] [code-server]` | **只讀**：證明 dev-e 上的應用回到它的基準（標記名稱與 sha256 等於基準還原後的讀取、code-server 真實登入、引擎狀態、健康檢查網址、基準備份仍在且以設備金鑰加密、dev-e 仍是 network none）；不建立、不備份、不還原；證據在 `~/.woowbk-lab/evidence/batch2-lab/<時間>-verify/` |
| `compare_batch2.py [nextcloud] [code-server] [opendesign]` | 只讀比對正式主機與 dev-e 已安裝的檔案、env 鍵（值只顯示調校用的鍵）、目錄項目與每個容器的映像 ID |
| `deploy-demo.sh <a\|b> [--notes N] [--files M] [--title T] [--no-seed]` | 不經引擎、以 appowner 手動部署 woowbk-demo（拉取 postgres、建置應用映像、安裝 Quadlet、daemon-reload、seed） |
| `deploy-dirs.sh <a\|b> [--items N] [--delete K] [--title T] [--owner-note T] [--seed S] [--no-seed]` | 同上，部署主機資料夾示範應用 woowbk-dirs（`catalog-examples/woowbk-dirs/README.md`）：複製到 `/opt/woowbk-dirs`、拉取 postgres（已有則略過）、建置 `localhost/woowbk-dirs-app:1`、安裝 Quadlet、seed（密鑰、設定檔、主機資料夾與容器帳號擁有者、資料庫角色與第二個資料庫、項目） |
| `dirs-catalog.sh <a\|b> install\|remove\|status` | 以 root 安裝或移除 woowbk-dirs 的受信任目錄項目（`/etc/woowtech-cockpit/backup/apps/woowbk-dirs.json`）與 Quadlet 範本，並列出已安裝引擎對它的判斷（沒有主機資料夾支援的引擎回報「不支援的欄位：data_dirs」並略過此應用） |
| `teardown-dirs.sh <a\|b> [--keep-image]` | 以擁有者身分移除整個 woowbk-dirs 部署（停止並解除遮蔽服務、測試 drop-in、Quadlet、容器、密鑰、網路、設定檔、兩個主機資料夾與其 `.woowbk-new-*`／`.woowbk-old-*`、應用映像），列出剩下的東西（必須是空的）；備份與目錄項目不動 |
| `subids.sh <a\|b> [START:COUNT --reset-storage]` | 顯示 appowner 的 subuid／subgid 與實際 `uid_map`；給範圍時先拆除兩個示範應用、確認家目錄沒有其他 ID 的檔案，再以舊對應 `podman system reset`、改寫 `/etc/subuid`／`/etc/subgid`、`podman system migrate` 並核對新對應（之後映像要重新取得或由備份還原）。`woowbk-provision` 會保留設備上有效的範圍 |
| `verify-device.sh <a\|b\|c\|d> [--no-browser]` | 實測：systemd `running`、Cockpit socket、user manager、巢狀 podman（alpine、uid map 等於設備 `/etc/subuid` 的範圍、`--memory`）、Quadlet 產生器、Playwright 登入並開啟管理員存取 |
| `cockpit-login.mjs <a\|b\|c\|d>` | Playwright：HTTPS 登入 devadmin → 開啟管理員存取 → `cockpit.spawn(['id','-u'], {superuser:'require'})` 必須為 0；截圖存於 `~/.woowbk-lab/evidence/lab/`（只在未輸入密碼或密碼欄消失後截圖） |
| `status.sh` | 各設備的狀態、systemd、記憶體、subuid 範圍、兩個示範應用的 `/healthz`（`demo-healthz` 18090、`dirs-healthz` 18091；000 為未部署或停止）；dev-c（存在時）改列目錄項目的健康網址：`odoo=`18069／18080、`n8n=`15678 readiness／15679；dev-d 列 `omnigent=`8000、`hermes=`18642／18644、`headscale=`29090／23000（302）與 `emqx-dashboard=`18083 |

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

## dev-c：正式主機 Odoo 與 n8n 的複本（HA 匯入測試）

**用途**：測試「把 Home Assistant 附加元件的備份匯入 Podman 的 Odoo 與 n8n」。dev-c 跑本主機這兩個應用的真實複本：映像 ID
相同、同樣的套件安裝程式、同樣的單元／容器／資料卷／密鑰／網路名稱與連接埠，所以正式主機的目錄項目 `odoo.json`、`n8n.json`
只改 `owner` 就能用。密鑰全部在設備內重新產生；沒有複製正式主機的任何密鑰或應用資料。2026-11-18 建置。

| 項目 | woowbk-dev-c |
| --- | --- |
| Cockpit／appowner | https://127.0.0.1:19093；appowner UID 1013，subuid／subgid `10000:55000` |
| 資源上限 | `--memory 3g --cpus 2`（10 個巢狀容器；閒置約 0.95 GB） |
| 私有 registry | `--add-host jcr-prod.woowtech.io:127.0.0.1`：設備內不可能從它拉映像 |
| 額外套件 | python3-nacl 1.5.0-4build1、python3-cryptography 41.0.7-4ubuntu0.4（只在 dev-c） |
| Odoo 18（tenant） | `odoo-db`／`odoo`／`odoo-gateway`，127.0.0.1:18069 與 :18080；套件 `~/migration-w2/Woow_podman_odoo`（138d10c） |
| n8n（佇列模式） | 7 個單元＋`n8n.target`，0.0.0.0:15678 與 :15679（只在設備的網路命名空間內）；套件 `~/quadlet-w1/Woow_podman_n8n`（2ac1ae2） |
| 備份引擎 | feat/ha-import 工作樹 03f60ee（2026.11.17.1），只有 `odoo`、`n8n` 兩個目錄項目；設備金鑰已建立，緊急金鑰 `~/.woowbk-lab/secrets/dev-c-kit.txt`（0600，實驗室拋棄式） |

**建置**（重設後照做即可）：

```bash
tests/e2e/lab/up.sh c && tests/e2e/lab/verify-device.sh c --no-browser
tests/e2e/lab/deploy-prodlike.sh c --odoo-repo <Woow_podman_odoo，含 138d10c> --n8n-repo <Woow_podman_n8n> \
    --cockpit-src <要測的 Woow_cockpit 工作樹>
python3 -I tests/e2e/lab/prodlike_baseline.py
```

* `packages`：設備內 `apt-get install python3-nacl python3-cryptography`。
* `images`：7 個映像從本主機自己的儲存以 `podman save … | labpodman exec -i woowbk-dev-c woowbk-owner podman load` 串流進去
  （約 6 分鐘、4.9 GB；剩餘空間要保持 ≥ 20 GiB）。主機上只執行 `podman image inspect` 與 `podman save`，從不拉取。預設的
  docker-archive 帶不了 zstd 層（n8n：`zstd compression is not supported for docker images`），所以 n8n 與 tenant-ha 用
  `--format oci-archive`（podman 存檔時會在 /var/tmp 暫存一份）。映像 ID 與主機相同，manifest 摘要則會改變，所以 3 個以摘要固定的參照要改成載入後的摘要。
* `odoo`：`git archive` 複製套件；設備內的副本把 gateway 映像的摘要改成載入後的（`quadlet/optional/odoo-gateway.container`、
  `scripts/common.sh` 各一行）；`odoo18.env` 由 `config/profiles/tenant-cloud.profile` 產生（映像參照、`DEFAULT_DB=odoo`、
  實驗室登入帳號 `labadmin@woowbk-dev-c.lab`）；`scripts/install.sh`：產生密鑰、tenant 初始化（角色 odoo NOCREATEDB、資料庫
  odoo 為 C 定序、pg_trgm 1.6＋vector 0.8.6、`-i base`、第一位管理員）、`upgrade-gate.sh --adopt-fresh`（標記和正式主機的值相同：
  digest＝映像 ID dd0982f3…、core_date 18.0.20260926）、關閉資料庫管理員（`LIST_DB=False`、`^odoo$`）；smoke 26 通過、0 失敗、
  1 警告（A7，tenant 模式本來就略過）。
* `n8n`：`n8n.env` 是主機的 18 個鍵（queue、webhook 處理程序、`N8N_QUEUE_DISABLE_MAIN_WEBHOOKS=true`、`HOST_BIND=0.0.0.0`），
  主機的區網位址換成 127.0.0.1；`scripts/install.sh`；smoke 全部通過。和正式主機一樣**沒有**建立 n8n 擁有者帳號
  （`isInstanceOwnerSetUp=false`）；加密金鑰由 n8n 第一次啟動時自己產生。
* `cockpit`：`deploy-src.sh c --src …`（不加示範目錄項目）、主機的 `/etc/woowtech-cockpit/backup/apps/{odoo,n8n}.json` 只把
  `owner` 改成 appowner、設備金鑰（key-init → key-kit → key-confirm）；`check`：`engine.sh c status` 兩個應用 running、沒有問題，
  四個健康網址 200。

**映像**（ID 兩邊相同，tenant-ha 的 ID 正是升級閘道標記用的值）：

| 正式主機 | dev-c 使用的參照 | 映像 ID |
| --- | --- | --- |
| `localhost/woow-odoo-tenant-ha:20261101.1152-51856b0@sha256:f259166a…` | `…@sha256:b128b97d99ab2cc83d16eba984eb6e603fef622c5b655a55d0984727fd5b51a6` | `dd0982f37ae8…` |
| `jcr-prod.woowtech.io/woow-paas-docker-local/paas-postgres:17.11-20260928.1549@sha256:dbd1fed8…` | `…@sha256:7a474eaf7bf2ccb167430ae1e30152f72d004d66efd671812ebaee0486511e90` | `f4fb9dc1e341` |
| `docker.io/nginxinc/nginx-unprivileged@sha256:65e3e85d…`（沒有標籤） | `docker.io/nginxinc/nginx-unprivileged:1.27-alpine@sha256:7b40c8ed6a73bda24d7510e3be1db31a19878acf65062271302a8a7aafd1682e` | `47ce8258a10e` |
| `docker.io/n8nio/n8n:2.43.6`、`runners:2.43.6` | 相同 | `c8d7cd6bf08e`、`28c5a510d762` |
| `docker.io/library/postgres:16.15-alpine`、`docker.io/valkey/valkey:8.1.11-alpine` | 相同 | `4278d7b1e3de`、`650ff8153447` |

**產生的密鑰**（dev-c 自己的，值從不顯示）：Odoo `odoo18-postgres-password`、`odoo18-admin-password`、
`odoo18-postgres-super-password`、`odoo18-odoo-admin-password`（各 44 個英數字）、`odoo18-odoo-conf`（含前兩個的設定檔）、
`odoo18-gateway-conf`；n8n `n8n-db-password`（32）、`n8n-runners-auth-token`（64）、`n8n-valkey-password`（48）與
`n8n_n8n_data/config` 的加密金鑰；另有上述設備金鑰。devadmin 密碼和其他設備共用。

**和正式主機的差異**（逐檔比對的結果）：

1. 帳號：appowner UID 1013、subuid `10000:55000`（主機的應用擁有者 UID 1000、`100000:65536`）。
2. 目錄項目：只有 `owner`。
3. Quadlet：17 個檔案、`n8n.target`、`n8n-task-runners.json`、`start-valkey.sh` 逐位元組相同，只有 3 個摘要不同：`odoo.container`
   的 `Image=` 與 `ExecStartPre=… --image`、`odoo-db.container` 與 `odoo-gateway.container` 的 `Image=`（見映像表）。
4. 套件：主機的 `~/migration-w2/Woow_podman_odoo` 是 c578b8a，缺 #10 的 `ODOO_TENANT_FRESH` 修正，無法全新安裝 tenant；dev-c 用
   138d10c（產生的單元相同），再加上 gateway 摘要那兩行。n8n 與主機同為 2ac1ae2。
5. `odoo18.env`：`WOOW_ODOO_IMAGE`、`WOOW_ODOO_DB_IMAGE`（摘要）、`WOOW_ODOO_ADMIN_LOGIN`（實驗室帳號），其餘 23 個鍵相同。
   `n8n.env`：`N8N_HOST`、`N8N_WEBHOOK_URL`、`N8N_EDITOR_BASE_URL` 用 127.0.0.1（主機用自己的區網位址），其餘 15 個鍵相同（行序不同）。
6. 資料：全新安裝。Odoo 資料庫 odoo 只安裝 12 個模組（主機 26 個，含 awesome_clicker、mail_fetchmail_durable，22 個附件）；
   n8n 和主機一樣是空的（1 個空殼使用者、沒有工作流程與憑證）。
7. dev-c 沒有的：主機的其他應用、接在 `odoo18-network`／`n8n-network` 上的 odoo-mcp-admin／n8n-mcp-admin、舊的 `odoo18-db-data`
   資料卷、`odoo18-odoo_{auto,fresh,parity}_20261110-admin-password` 這些舊密鑰、套件的每日 `odoo18-backup.timer`。
8. 網路：n8n 的 0.0.0.0 只在設備內；主機只連得到 Cockpit（127.0.0.1:19093）。

**基準**（`prodlike_baseline.py`，2026-11-18，20／20 通過，證據 `~/.woowbk-lab/evidence/prodlike/20261118T175223-baseline/`）：

| 應用 | 加密備份（不含映像） | 大小 | 備份／停機 | 原位還原 | 還原前備份 |
| --- | --- | --- | --- | --- | --- |
| odoo | `20261118T095247Z-388c9bd7` | 12.6 MB | 25.8 秒／11 秒 | 33.5 秒 | `20261118T095320Z-5d8a82bb` |
| n8n | `20261118T095520Z-33eb7474` | 133 KB | 98.0 秒／49 秒 | 147.3 秒 | `20261118T095609Z-fc898f42` |

備份前寫入的標記資料列在還原後仍在、備份後寫入的消失；健康檢查全部通過；之後兩個套件自己的 smoke 也都通過，Odoo 的升級閘道
回報 already completed（和正式主機每天的紀錄一樣）。這 4 份備份留在 dev-c，是實驗室資料。設備重新啟動（`down.sh c`、
`up.sh c`）後，兩個應用由 linger 自動啟動，約 1 分鐘內健康檢查全部 200。

**重設**：`tests/e2e/lab/reset.sh c --up` 刪除容器與三個資料卷（映像、應用、備份、設備金鑰全部消失），再照「建置」重跑
（`deploy-prodlike.sh` 約 10 分鐘，其中映像約 6 分鐘、Odoo 與 n8n 的安裝各約 2 分鐘）。新的設備金鑰會覆寫 `dev-c-kit.txt`，之前下載的 dev-c 備份就打不開了。只更新引擎與頁面：
`deploy-src.sh c --src <工作樹>`。dev-c 不用時以 `down.sh c` 停止（約 1 GB 記憶體）。

## dev-d：正式主機 Omnigent、Hermes、EMQX 與 Headscale 的複本（HA 匯入第一批）

**用途**：測試「把 Home Assistant 附加元件的備份匯入 Podman 的 Omnigent、Hermes、EMQX 與 Headscale」（HA 匯入第一批）。dev-d 跑本主機
這四個應用的真實複本：映像 ID 相同、同樣的套件安裝程式與版本（正式主機實際執行的提交）、同樣的單元／容器／資料卷／密鑰／網路名稱與
連接埠，所以正式主機的目錄項目幾乎只改 `owner` 就能用（Headscale 另外拿掉 ngrok 的部分，見差異 2）。密鑰全部在設備內重新產生；
沒有複製正式主機的任何密鑰、權杖或應用資料。2026-11-19 建置。

| 項目 | woowbk-dev-d |
| --- | --- |
| Cockpit／appowner | https://127.0.0.1:19094；appowner UID 1019，subuid／subgid `10000:55000` |
| 資源上限 | `--memory 4g --cpus 2`（11 個巢狀容器；實測見下） |
| 額外套件 | jq 1.7.1-3ubuntu0.24.04.2（Omnigent 的安裝程式需要）、python3-nacl 1.5.0-4build1、python3-cryptography 41.0.7-4ubuntu0.4（HA 備份） |
| Omnigent 0.21.0 | `omnigent-postgres`／`omnigent-server`／`omnigent-runner`＋`omnigent-server-health.timer`，127.0.0.1:8000；套件 `~/Woow_podman_omnigent_package`（6e4f0c0，0.21.0-2） |
| Hermes v0.22.5 | `hermes-postgres`（容器 `hermes-postgresql`）／`hermes-redis`／`hermes-agent`＋`hermes-provision.service`，127.0.0.1:18642、:19119、:18644；套件 `~/Woow_podman_hermes`（63c8be1） |
| EMQX 5.8.9 | `emqx`（容器 `woow-emqx`）／`emqx-entrance`，127.0.0.1:1883、:8883、:8083、:8084、:18083；套件 `~/Woow_podman_emqx`（ea5886c） |
| Headscale 0.29.4＋Headplane 0.7.1 | `headscale`／`headplane`／`headscale-entrance`（沒有 `headscale-ngrok`），127.0.0.1:28080、:29090（metrics）、:23000（Headplane 入口）；套件 `~/Woow_podman_vpn_headscale_package`（0afdfa4） |
| 備份引擎 | main bb23531（2026.11.19.2，與正式主機安裝的相同），只有這四個目錄項目；設備金鑰已建立，緊急金鑰 `~/.woowbk-lab/secrets/dev-d-kit.txt`（0600，實驗室拋棄式） |

**建置**（重設後照做即可）：

```bash
tests/e2e/lab/up.sh d && tests/e2e/lab/verify-device.sh d --no-browser
tests/e2e/lab/deploy-batch1.sh d --omnigent-repo <Woow_podman_omnigent_package> --hermes-repo <Woow_podman_hermes> \
    --emqx-repo <Woow_podman_emqx> --headscale-repo <Woow_podman_vpn_headscale_package> \
    --cockpit-src <要測的 Woow_cockpit 樹，例如 git archive 的 main>
python3 -I tests/e2e/lab/batch1_baseline.py
```

* 每個套件複製的是正式主機實際執行的提交（`deploy-batch1.sh` 的 `REV`，可用 `--<應用>-rev` 改），不是 checkout 的 HEAD：正式主機已安裝的
  Quadlet、單元與設定檔逐一以範本比對（`@@變數@@` 視為任意值）。Omnigent 6e4f0c0 與 EMQX ea5886c 是主機 checkout 的 HEAD（EMQX 的樹與
  main 937ab4b 相同）；Hermes 63c8be1（main）安裝出來的檔案與 0.23.1（f4d0757，11-06 22:28 提交，正式主機的安裝清單寫於 22:31）相同，之後只改了文件；
  Headscale 0afdfa4 是 origin/main，主機的 checkout 停在舊分支 d0c795d，正式主機的檔案是由 0afdfa4 產生的。
* `packages`：設備內 `apt-get install jq python3-nacl python3-cryptography`。
* `images`：10 個映像從本主機自己的儲存以 `podman save … | labpodman exec -i woowbk-dev-d woowbk-owner podman load` 串流進去
  （約 10 分鐘、6.7 GB；剩餘空間要保持 ≥ 20 GiB）。主機上只執行 `podman image inspect` 與 `podman save`，從不拉取。都沒有 zstd 層，
  一律用 docker-archive。以摘要固定的 6 個映像（7 個參照）在套件副本中改成載入後的摘要（各應用階段的 `repin`，只改 `quadlet/*.container`
  的 `Image=`）。Headplane 映像有一個項目 `/home/nonroot`（distroless 的目錄）屬於 65532:65532，超出 appowner 的巢狀範圍（容器 ID 1–55000；
  設備本身只有 65536 個 ID），所以只有這一次 load 加上 `--storage-opt ignore_chown_errors=true`：該目錄改屬容器的 root，映像 ID 仍與主機相同
  （ID 是設定的摘要），Headplane 以 root 執行、不使用這個目錄。
* `omnigent`：套件的 `scripts/install.sh --no-build`；`omnigent.env` 由套件範例產生（值與主機相同）；產生 4 個密鑰、管理員 `admin`、非管理員
  `operator`（runner 以它登入）；smoke 17 通過、0 失敗。
* `hermes`：`scripts/install.sh --no-llm --no-build --set HERMES_PASEO_EXTRA_ORIGIN=http://127.0.0.1:19119 --set WOOW_HERMES_MEMORY=6144m`
  （這兩個是主機的值）；`hermes.env` 其餘照範例：沒有任何模型供應商金鑰、公開網址是範例的 `http://localhost:19119`；產生 5 個密鑰；
  provisioning 完成；smoke 27 通過、0 失敗、2 個警告（儀表板改用登入表單、`podman inspect` 看得到 env 型密鑰，兩者都是套件本身的行為）。
* `emqx`：`scripts/install.sh --accept-defaults`（`emqx.env` 即範例，只有 `WOOW_EMQX_BIND` 與主機不同）；產生 4 個密鑰（含 MQTT 使用者
  `woow` 的 bootstrap CSV）；smoke 16 通過、0 失敗、1 個警告（同上的 podman 行為）。smoke 會以摘要拉取 `eclipse-mosquitto:2.0.22@sha256:212f89e1…`
  （MQTT 測試用戶端，不是應用映像，設備內留有一份）。
* `headscale`：`scripts/install.sh --accept-defaults --no-build`（`headscale.env` 即範例：`HEADSCALE_NGROK_ENABLED=false`，所以不安裝
  `headscale-ngrok.container`，也不需要 ngrok 權杖）；產生 Headplane cookie 與入口密碼（htpasswd 只有雜湊）、由 Headscale 發出 Headplane 的
  API 金鑰、建立使用者 `default`；smoke 28 通過、0 失敗、1 個警告（server_url 是回送位址）。
* `cockpit`：`deploy-src.sh d --src …`（不加示範目錄項目）、主機的 `/etc/woowtech-cockpit/backup/apps/{omnigent,hermes,emqx,headscale}.json`
  只把 `owner` 改成 appowner（Headscale 見差異 2）、設備金鑰（key-init → key-kit → key-confirm）；`check`：`engine.sh d status` 四個應用
  running、沒有問題、單元全部 active，目錄項目的五個健康網址都是預期的 200／302，13 個使用者單元 active，沒有失敗的使用者單元。

**映像**（ID 兩邊相同）：

| 正式主機 Quadlet 的參照 | dev-d 使用的參照 | 映像 ID |
| --- | --- | --- |
| `docker.io/library/postgres:16.15-alpine3.24@sha256:aa6cb33c…`（Omnigent） | `…@sha256:8d16e6f18cc33ffb153211c40b45056a3589d49c245530469843b368d6786069` | `4278d7b1e3de` |
| `ghcr.io/omnigent-ai/omnigent-server:v0.21.0@sha256:9bba2964…` | `…@sha256:289b90a748664c46f049b7545f651bbc86c27ce7f6f9f2c0a16f9b37eb6f12d5` | `545fa9ea7c19` |
| `localhost/woow-omnigent-runner:0.21.0-2` | 相同 | `68794c7302df` |
| `localhost/woow-hermes-agent:v0.22.5-woow4` | 相同 | `9a40b79b6149` |
| `docker.io/library/postgres:15.19@sha256:9b1d34ad…`（Hermes） | `…@sha256:c414d6b9e7afb0cbb26e67a351266b2c32056d010a42b4b4940cdc8c385afafb` | `40710ae20139` |
| `docker.io/library/redis:7.4.11-alpine@sha256:ff02b58f…` | `…@sha256:f69f4c190a0dbdb3877abe028f13a6a9568a978a49514dd09bd3c0a2c8224914` | `5509c0097c60` |
| `docker.io/emqx/emqx:5.8.9@sha256:35b46f7a…` | `…@sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937` | `3f60addfad2b` |
| `docker.io/nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85d…`（EMQX 與 Headscale 的入口） | `…@sha256:7b40c8ed6a73bda24d7510e3be1db31a19878acf65062271302a8a7aafd1682e`（與 dev-c 的 gateway 相同） | `47ce8258a10e` |
| `localhost/woow-headscale:0.29.4-r1` | 相同 | `a5f7b9715dea` |
| `localhost/woow-headplane:0.7.1-woow2` | 相同（`/home/nonroot` 屬於容器 root，見上） | `0b4481f9ad05` |

**產生的密鑰**（dev-d 自己的，值從不顯示）：Omnigent `omnigent-postgres-password`（32）、`omnigent-admin-password`（24）、
`omnigent-runner-password`（24）、`omnigent-database-url`；Hermes `hermes-api-server-key`、`hermes-webhook-secret`、
`hermes-dashboard-session-secret`（各 64）、`hermes-dashboard-password`（32）、`hermes-postgres-password`（44）；EMQX
`woow-emqx-dashboard-password`、`woow-emqx-node-cookie`、`woow-emqx-mqtt-password`（各 32）、`woow-emqx-mqtt-bootstrap`；Headscale
`headscale-headplane-cookie`、`headscale-entrance-password`（各 32）、`headscale-headplane-api-key`（Headscale 發出）與資料卷內 Headscale 自己的
`noise_private.key`；另有上述設備金鑰，以及基準標記帳號的密碼 `~/.woowbk-lab/secrets/dev-d-markers.json`（0600）。devadmin 密碼和其他設備共用。

**和正式主機的差異**（`python3 -I tests/e2e/lab/compare_batch1.py` 逐檔比對兩邊已安裝的 Quadlet、單元、設定檔、env 檔與目錄項目，
只讀；2026-11-19 的結果在 `~/.woowbk-lab/evidence/batch1-lab/deploy/compare-prod.txt`）：

1. 帳號：appowner UID 1019、subuid `10000:55000`（主機的應用擁有者 UID 1000、`100000:65536`）。
2. 目錄項目：Omnigent、Hermes、EMQX 只有 `owner`；Headscale 另外沒有 `headscale-ngrok.container`、`headscale-ngrok.service` 與密鑰
   `headscale-ngrok-authtoken`（實驗室沒有 ngrok 權杖，這個單元就不存在；留著的話狀態會是「部分 Quadlet 設定檔不存在」）。描述文字未改。
3. Quadlet 與單元：Omnigent 7＋2、Hermes 7＋1、EMQX 5、Headscale 7 個檔案中，除了下列各行之外逐位元組相同：7 個 `Image=` 摘要
   （`omnigent-postgres`、`omnigent-server`、`hermes-postgres`、`hermes-redis`、`emqx`、`emqx-entrance`、`headscale-entrance`，見映像表）；
   `emqx.container` 的 5 個 `PublishPort=` 與 `headscale.container` 的 28080 綁 127.0.0.1（主機綁自己的區網位址，設備裡沒有這個位址）；
   沒有 `headscale-ngrok.container`。
4. 設定檔：EMQX 的 `base.hocon`、`acl.conf`、`entrance.conf`，Headscale 的 `policy.json`、`extra_records.json`、`nginx.conf`、`ngrok-sync.py` 相同；
   `headscale/config.yaml` 的 `server_url` 與 `headplane/config.yaml` 的 `public_url` 是 `http://localhost:28080`（主機是它的 ngrok
   公開網址）；`htpasswd` 是另一個產生的密碼的雜湊。
5. env 檔（比對只列不同的鍵，祕密只說有沒有值）：`omnigent.env` 的值相同（主機的檔案來自較舊的範例，有一行註解不同）；
   `hermes.env` 的鍵相同、行序不同，`HERMES_DASHBOARD_PUBLIC_URL`／`HERMES_BASE_URL` 是範例的 `http://localhost:19119`（主機是
   它的 Cloudflare 公開網址），`OPENROUTER_API_KEY`、`GITHUB_TOKEN`、`LITELLM_API_KEY` 是空的（主機有值；因此以 `--no-llm` 安裝）；
   `emqx.env` 只有 `WOOW_EMQX_BIND=127.0.0.1`；`headscale.env` 的鍵相同、行序不同，`WOOW_HEADSCALE_BIND=127.0.0.1`、
   `HEADSCALE_SERVER_URL=http://localhost:28080`、`HEADSCALE_NGROK_ENABLED=false`、`HEADSCALE_NGROK_DOMAIN` 空白。
6. 套件：見上（Headscale 用 origin/main 0afdfa4，不是主機 checkout 的 HEAD）。套件副本只改了第 3 點的 `Image=` 摘要。
7. 映像：ID 全部相同；Headplane 映像內 `/home/nonroot` 的擁有者不同（見 `images`）。設備內多一個 smoke 拉取的 `eclipse-mosquitto` 測試用戶端。
8. 資料：全新安裝，加上基準標記（見下）。Omnigent 只有 `admin`、`operator` 與標記，runner 的 pi 沒有登入任何供應商（主機的擁有者登入過）；
   Hermes 沒有供應商金鑰、沒有 Omnigent／Paseo 外掛配對，資料卷只有種子技能與設定（主機的 `hermes-data` 約 2.3 GB，其中 `omnigent-plugin`
   1.2 GB、`plugin-data` 0.75 GB）；EMQX 是新的 Mnesia（`admin`、`woow`）；Headscale 有使用者 `default`，除了基準標記沒有節點（主機目前也是 0 個節點）。
9. dev-d 沒有的：主機的其他應用；接在這四個應用上的 `hermes-mcp-admin`、`emqx-mcp-admin`、`headscale-mcp-admin` 與 `woow-mcp-edge`；Hermes 的
   Cloudflare 公開網址與它使用的 LiteLLM；Headscale 的 ngrok 公開網址；EMQX 在主機上的 MQTT 用戶端（Podman 的 Home Assistant）；主機上另外加的
   `hermes-local-health.timer`（11-08 手動建立，不屬於套件）、`podman-hc-watchdog`，以及舊的 Headscale soak／closeout／`woow_headscale*` 單元。
10. 網路：所有應用埠只綁在設備內的 127.0.0.1；主機只連得到 Cockpit（127.0.0.1:19094）。
11. 套件安裝程式內建的 Quadlet 驗證（quadlet-lib `ql_dryrun --verify`）在設備內以暫時的 `XDG_RUNTIME_DIR` 執行 `systemd-analyze --user verify`，
    和正式主機安裝時一樣；這不碰設備或主機的 user manager socket。

**基準**（`batch1_baseline.py`，2026-11-19，44／44 通過，證據 `~/.woowbk-lab/evidence/batch1-lab/20261119T152014-baseline/`）：

| 應用 | 標記（都叫 `woowbk-lab-baseline`） | 加密備份（不含映像） | 大小 | 備份／停機 | 原位還原／無法使用 | 還原前備份 |
| --- | --- | --- | --- | --- | --- | --- |
| omnigent | 非管理員使用者（受邀註冊）、專案、暫停的每年排程工作（REST API） | `20261119T072103Z-ea792b52` | 6.3 MiB | 47.8 秒／13 秒 | 75.7 秒／55.3 秒 | `20261119T072159Z-1c5f2680` |
| hermes | `state.db` 的工作階段（1 則訊息）、`MEMORY.md` 項目、暫停的 cron 工作（容器內 Hermes 自己的程式碼，hermes 使用者） | `20261119T072434Z-45b29e52` | 1.1 MiB | 97.6 秒／32 秒 | 142.5 秒／107.4 秒 | `20261119T072615Z-48515a01` |
| emqx | 內建資料庫認證器的 MQTT 使用者、保留訊息 `woowbk-lab/baseline`、封鎖的 client ID（REST API） | `20261119T072831Z-168aaa02` | 30 KiB | 34.2 秒／17 秒 | 22.4 秒／14.8 秒 | `20261119T072904Z-9026af1d` |
| headscale | 使用者、可重複使用的預先授權金鑰、節點、MagicDNS 額外紀錄（headscale CLI） | `20261119T072939Z-d52b60b2` | 30 KiB | 15.7 秒／7 秒 | 36.2 秒／26.9 秒 | `20261119T073006Z-4343b4b5` |

備份前建立的標記在還原後仍在、備份後寫入的 `woowbk-lab-after` 消失；Omnigent 的資料核對（資料庫與兩個資料卷）一致；目錄項目的健康檢查
全部通過；四個應用 running、沒有問題。基準標記留在應用裡，所以目前的資料等於這四份基準備份：之後的測試（例如匯入 HA 備份）結束時還原
它們就回到這個狀態，可用 `woowbk-owner python3 -I -c "$(cat tests/e2e/lab/batch1_markers.py)" <應用> read` 核對（標記帳號的密碼在
`~/.woowbk-lab/secrets/dev-d-markers.json`）。這 8 份備份留在 dev-d，是實驗室資料（較早幾輪試跑的備份已刪除）。

* EMQX 的目錄項目沒有健康網址（正式主機也一樣），所以備份與還原作業在單元啟動後就結束，EMQX 的 API 還要十幾秒才就緒：入口先回 502，
  接著內建資料庫認證器回 400 `not_initialized`。`batch1_markers.py` 對這兩種回應與拒絕連線會重試（最多 180 秒）。
* Hermes 的備份與還原時間主要是等健康檢查：代理重新啟動後約 60–90 秒 `/health` 才回 200（`HealthStartPeriod=90s`）。

**記憶體與磁碟（實測）**：主機端每 2 秒讀設備 cgroup 的 `memory.stat`。anon＋kernel＋shmem 最高：串流映像時 0.3 GiB（其餘是 page cache）、
四個安裝時 1.6 GiB、基準備份與還原時 1.8 GiB，閒置約 1.5 GiB（`labpodman stats` 約 1.1 GB；最大的是 hermes-agent 約 430 MB，其次
omnigent-runner、omnigent-server、woow-emqx、headplane 各 120–180 MB）。含 page cache 的 cgroup 用量最高 2.9 GiB，`memory.events` 的
max、oom、oom_kill 都是 0。上限 4g 為 HA 匯入時的拋棄式容器（tempctr 每個上限 2 GiB）留空間；這段期間主機可用記憶體最低約 4.7 GB。
設備的 home 資料卷 8.0 GB（其中映像 6.7 GB），備份目錄 15 MB。

**重設**：`tests/e2e/lab/reset.sh d --up` 刪除容器與三個資料卷（映像、應用、備份、設備金鑰全部消失），再照「建置」重跑（`deploy-batch1.sh`
約 15 分鐘，其中映像約 10 分鐘、四個安裝合計約 5 分鐘）。新的設備金鑰會覆寫 `dev-d-kit.txt`，之前下載的 dev-d 備份就打不開了；
`dev-d-markers.json` 保留，下一次基準會沿用。只更新引擎與頁面：`deploy-src.sh d --src <工作樹>`。dev-d 不用時以 `down.sh d` 停止。

### Hermes 真實還原（`hermes_real_ha.py`，hermes-real 線，2026-11-23）

擁有者 2026-11-23 明確授權實測 Hermes。把批次一的**真實 x86 HA 備份**（附加元件 `9c1a67eb_woow-hermes` 0.1.14，Hermes v0.22.5，
結構 32，5 個對話／15 則訊息，兩個建在 view 上的 FTS5 表）以**產品路徑**匯入 dev-d 的 Hermes：引擎是本工作樹（`deploy-src.sh d` 安裝），
每一步都是頁面送出的 helper 指令（root、stdin 一個 JSON、回一個 JSON）。b1 驅動程式（`ha_import_b1_e2e.py`）本身的真實入口仍然
fail-closed；本程式只重用它的 helper 呼叫、`Secrets` 讀取器、遮蔽後的證據與 Hermes 驗證。

```bash
python3 -I tests/e2e/lab/hermes_real_capture.py --private=<~/.woowbk-lab/evidence/hermes-real/…-stdout.txt> \
    tests/e2e/lab/evidence/hermes-real-20261123/attempt-NN-<scope>.json <scope> -- \
    python3 -I tests/e2e/lab/hermes_real_ha.py packages setup before check import:x86-enc   # 之後 import:x86-plain import:x86-unc kit-baseline cleanup leaks
```

* 一次執行＝一次持有 `/tmp/woowbk-dev-d-mutation.lock`（`/tmp/woowbk-dev-d-emqx-main-waiting` 存在時不取鎖，步驟之間看到它就讓出），
  前後都跑 `owner.sh d --verify-isolation`，每步前檢查 dev-d cgroup 餘裕 ≥ 1.5 GiB、主機 MemAvailable ≥ 1 GiB、磁碟 ≥ 13 GiB；
  持有超過 30 分鐘就不再開始新步驟。工作樹必須乾淨（先提交再實測）。
* `packages`：dev-d 在 11-20 以 network none 重建後少了本節「建置」裝的 `python3-nacl`、`python3-cryptography`（HA 加密備份需要）；
  設備沒有網路，所以由主機 `apt-get download`（Ubuntu 24.04 noble 官方庫，apt 依簽章索引驗證；dev-d 也是 24.04）下載
  `libsodium23`、`python3-cffi-backend`、`python3-nacl`、`python3-cryptography`，以 `labpodman cp` 放入再 `dpkg -i`。
* `setup`：先 `systemctl mask` 排程計時器（共用實驗室，不要排程），`deploy-src.sh d --src <本樹> --no-demo-catalog`；Hermes 的目錄項目
  取自 dev-d **自己的** Hermes 基準備份 `20261119T072434Z-45b29e52` 附帶的設定（用 11-19 的緊急金鑰 `dev-d-kit.txt` 開，絕不顯示），
  以 `catalog-install` 原樣安裝；`key-init` 建立設備金鑰（不讀取其緊急金鑰；測試備份最後會刪除）。不讀正式主機的任何目錄項目。
* `before`：基準標記（`batch1_markers.py hermes read`）、檔案擁有者例外、Hermes 狀態摘要（對話與每則訊息的 sha256、記憶、技能、排程、
  看板、config.yaml、.env 的鍵名）。
* `check`：三份 HA 檔（store 內 SHA-256 與本機 fixture 相同）各跑一次 `ha-check-start`，結果等於來源事實。
* `import:<x86-enc|x86-plain|x86-unc>`：轉換、inspect、還原；經由 Hermes 本身驗證：儀表板 API 列出 HA 的 5 個對話（訊息數、來源、模型、
  標題、開始時間＝來源事實），每則訊息 API 內容＝state.db（id、role、sha256），全文搜尋 `/api/sessions/search`（FTS5，片段帶 `>>> <<<`）
  找到的對話＝容器內非 FTS 掃描的結果；兩個 FTS5 表在一致的複本上 `integrity-check` 通過；b1 驅動程式的 Hermes 檢查（儀表板密碼、
  記憶、技能、排程、看板、.env、webhook 簽章、API 金鑰）；重新啟動 hermes-agent 後再驗一次；以還原時產生的還原前備份回退，
  基準標記回來、HA 的資料與搜尋結果消失、狀態摘要等於 `before`。
* `kit-baseline`：以緊急金鑰還原 dev-d 的 Hermes 基準備份（頁面「輸入緊急金鑰」的路徑），標記與摘要回到 `before`。
* `cleanup`／`leaks`：刪除本測試的轉換與還原前備份；沒有作業的拋棄式容器、暫存資料夾、金鑰檔；引擎紀錄、日誌、run 目錄與
  run 開始後的設備日誌中沒有 HA 金鑰、HA 的 Hermes 測試秘密、緊急金鑰或 dev-d 的 Hermes 密鑰（只回傳次數）。
* 動態憑證（services-b，2026-11-23）：每次儀表板密碼登入都會**發出**工作階段 cookie `hermes_session_at`（必有）與
  `hermes_session_rt`（供應者有給才有；vendor hermes-agent v0.22.5 `hermes_cli/dashboard_auth/cookies.py:27-28`、`:86-95`）。
  continuity 與 b1 的 Hermes 檢查（這台的密碼一次、HA 的密碼一次＝應被拒）都經由有確認的事件傳輸
  （`event_device_python`）把拿到的值交給主機登錄後才繼續（共用片段 `drv.HERMES_ISSUE`，順序 `HERMES_AUTH`／`ISSUED_AUTH`）；
  每次登入在探測前就登記為一個宣告來源（`drv.ISSUED_SESSIONS`），`leaks` 在任何掃描之前，只要有一個宣告來源沒有登錄到值就失敗，
  並以一行 CHECK 記錄來源數與值數。值只在記憶體裡，所以 `leaks` 必須和登入在同一次執行。探測的子程序不繼承 stdin
  （事件模式下 stdin 是主機的確認通道）；儀表板 API 逾時或非 JSON 回應記為代碼 0（該項檢查失敗），不再讓整個探測結束。
* 每次儀表板呼叫的耗時（hermes-real，dbdf399）：continuity 與 b1 的 Hermes 探測都把每次呼叫記成「固定路徑（去掉查詢字串）、
  回應代碼、秒數」（不含任何值或 cookie），交回主機；主機把最慢的四次寫進私有 `run.log`。第 9、10 次嘗試的 x86-unc 都有一次
  儀表板 GET 超過 30 秒，當時沒有記錄是哪一個端點，之後就靠這一行找出來。檢查與逾時都沒有改。
* 沒有涵蓋：瀏覽器頁面本身（dev-d 不公開任何埠；helper 呼叫就是頁面送出的）、與模型對話（dev-d 以 `--no-llm` 安裝，HA 的設定指向
  HA 內部網址，匯入時已提醒）、ARM（Hermes 附加元件只有 amd64）。
* 鎖：像 `flock -w` 一樣阻塞等待；emqx-main 的等待檔存在時不取鎖（取到也立即放開）。只有在 emqx-main 的真實執行**持有**鎖
  （`/proc/<pid>/fdinfo` 有 `lock: FLOCK` 行）期間看到的那一份等待檔才視為過時；只開啟鎖檔（`flock -n` 失敗的重試）不算持有。
* 結果（2026-11-23）：見 `evidence/hermes-real-20261123/`（每次嘗試一份 JSON：固定狀態行、stdout SHA-256、來源提交、
  `commercial_acceptance: not-complete`）與 `status.json`。三種 x86 備份都在實驗室完整走完（轉換、inspect、還原、Hermes 本身提供
  對話／訊息／FTS5 搜尋、b1 的 Hermes 檢查、重新啟動後再驗、以還原前備份回退且摘要相同）：x86-enc 第 7、11 次，x86-plain 第 8、12 次，
  x86-unc 第 11 次（第 9、10 次只到回退，b1 檢查與重啟沒跑到）；緊急金鑰還原基準第 9、12 次；cleanup／leaks 第 9–12 次，
  其中第 11、12 次涵蓋登入發出的 cookie（9＋6 個宣告來源、18＋12 個值、0 命中）。
* 第 9、10 次 x86-unc 失敗的可能原因：第 12 次量到還原後**第一次** `GET /api/env` 要 17.72 秒（其他呼叫都 ≤ 3.71 秒）。vendor
  `hermes_cli/web_routers/config_env.py:259-269` → `hermes_cli/web_server_messaging.py:103-107` → `:79-82`：儀表板程序第一次
  建頻道清單時才執行 `discover_plugins()`，是一次性的冷啟動成本，主機負載約 22–25 時會更慢。第 9、10 次當時沒有記錄端點，
  所以「就是 `/api/env`」是推論，不是觀察。

## dev-e：正式主機 Nextcloud、code-server 與 OpenDesign 的複本（HA 匯入第二批）

**用途**：測試「把 Home Assistant 附加元件的備份匯入 Podman 的 OpenDesign、Nextcloud 與 code-server」（HA 匯入第二批，擁有者
2026-11-23 的決定 2 A）。dev-e 跑本主機這三個應用的真實複本：映像 ID 相同、同樣的套件安裝程式與版本（正式主機實際執行的提交）、
同樣的單元／容器／資料卷／密鑰／網路名稱與連接埠。密鑰全部在設備內重新產生；沒有複製正式主機的任何密鑰、權杖或應用資料。
2026-11-23 建置。**一次只跑一個應用**（見「輪替」）：21:04 起只執行 Nextcloud；OpenDesign（19:44）與 code-server（20:32）都在各自的真實匯入通過後輪替出去（映像移除，資料與基準備份保留）。輪替紀錄在 `tests/e2e/lab/evidence/batch2-lab-20261123/dev-e-rotations.json`。

| 項目 | woowbk-dev-e |
| --- | --- |
| 網路 | `--network none`、**沒有發布任何連接埠**：主機連不到它的 Cockpit 與應用，它也連不到任何網路（`owner.sh e --verify-isolation` 印出 `dev-e isolation: true none {}`）。只用 `owner.sh e`、`engine.sh e`、`exec.sh e` |
| appowner | UID 1025，subuid／subgid `10000:55000` |
| 資源上限 | `--memory 3g --cpus 2` |
| 額外套件 | 設備映像沒有、dev-e 也連不到 apt：python3-nacl 1.5.0-4build1、python3-cryptography 41.0.7-4ubuntu0.4（HA 加密備份）、jq 1.7.1-3ubuntu0.24.04.2，由同一個設備映像的拋棄式容器（實驗室儲存、唯一連網的步驟）下載 .deb 到 `~/.woowbk-lab/cache/debs-noble`（附 sha256），再複製進去以 dpkg 安裝 |
| OpenDesign 4.2.1（OpenDesign 0.24.1） | `open-design`／`open-design-mcp`／`open-design-nginx`／`open-design-terminal`，127.0.0.1:7456；套件 `~/Woow_podman_opendesign`（1067bc4，PR #17 的 head，上游合併為 bbbd4de）；Paseo 開啟，來源 `https://opendesign.lab.invalid`。**19:44 輪替出去**（真實匯入 85／85 通過之後）：單元停止、映像與 keep-id 複本移除（主機多出 12.07 GiB）；單元檔、env、密鑰、資料卷、目錄項目與基準備份保留。喚醒：`deploy-batch2.sh e images:opendesign`，再啟動四個單元 |
| Nextcloud 35.0.1＋Collabora | `nextcloud-db`／`-redis`／`-app`／`-office`／`-gateway`＋`nextcloud-cron.timer`，127.0.0.1:18081；套件 `~/Woow_podman_nextcloud_fresh`（19a7609，PR #7 的 head）。2026-11-23 17:11 已安裝（套件 smoke 全部通過、`check:nextcloud` 全綠），17:15 休眠（單元停止、映像移除，讓 OpenDesign 的真實匯入有磁碟空間），**21:04 喚醒**（五個映像以主機的 ID 重新複製、`nextcloud.target` 啟動、`check:nextcloud` 全綠），基準備份 `20261123T132013Z-34811d90` |
| code-server 4.139.1-8 | `code-server`＋`code-server-health.timer`，127.0.0.1:18443；套件 `~/Woow_podman_code_server_package`（tag 4.139.1-8＝e7dbbea），2026-11-23 20:08 以 `scripts/install.sh --no-build --yes` 安裝（全新密碼密鑰 `code-server-config`，套件 smoke 11／11，`check:code-server` 全綠）；正式主機沒有它的目錄項目（未納入），dev-e 用 codeserver-import 那一線的實驗室目錄項目 `tests/e2e/lab/catalog/woow-code-server.json`（三個資料卷、密鑰、env 檔與工作區 `~/Desktop`，擁有者決定 D1 b）。真實匯入 87／87 通過後 **20:32 輪替出去**（映像與 keep-id 複本移除，主機多出 10.62 GiB；資料卷、`~/Desktop`、密鑰、目錄項目與基準備份保留）。喚醒：`images:code-server` 再跑一次 `code-server` 階段 |
| 備份引擎 | lab/batch2-dev-e-20261123 79c0f8d（＝integration/ha-import-batch1-20261123 82ac971 加上實驗室腳本；匯入那一線跑的時候會換成自己的引擎），目錄項目 open-design、nextcloud、woow-code-server；設備金鑰 D4C6-F434-C5D0-659C，緊急金鑰 `~/.woowbk-lab/secrets/dev-e-kit.txt`（0600，實驗室拋棄式） |

**建置**（重設後照做即可；每個階段都可以重跑）：

```bash
tests/e2e/lab/up.sh e && tests/e2e/lab/verify-device.sh e
tests/e2e/lab/deploy-batch2.sh e packages images:opendesign
tests/e2e/lab/deploy-batch2.sh e --opendesign-repo ~/Woow_podman_opendesign opendesign
tests/e2e/lab/deploy-batch2.sh e --cockpit-src <要測的 Woow_cockpit 樹> cockpit check:opendesign
python3 -I tests/e2e/lab/batch2_baseline.py opendesign
python3 -I tests/e2e/lab/compare_batch2.py opendesign > ~/.woowbk-lab/evidence/batch2-lab/compare-prod-opendesign.txt
```

其他兩個應用（一次一個，見「輪替」）：`deploy-batch2.sh e images:nextcloud`，`deploy-batch2.sh e --nextcloud-repo ~/Woow_podman_nextcloud_fresh nextcloud`；
`deploy-batch2.sh e images:code-server`，`deploy-batch2.sh e --code-server-repo ~/.woowbk-lab/cache/repos/Woow_podman_code_server_package.git code-server`
（主機的 `~/Woow_podman_code_server_package` 停在沒有 tag 4.139.1-8 的舊分支；快取裡的是 GitHub main 89e6648 的裸複本，含 e7dbbea），
之後 `cockpit`（或已部署引擎時只跑 `catalog`）、`check:<應用>` 與 `batch2_baseline.py <應用>`。richdocuments 發行檔與 .deb 快取在 `~/.woowbk-lab/cache/`（sha256 固定）。

* `images[:應用]`：映像從本主機自己的儲存以映像 ID `podman save --format docker-dir --compress` **直接寫進 dev-e 的 home 資料卷**
  （主機那一側的 `/home/.woowbk-xfer`），再以 appowner `podman load`、以 ID 加上名稱、刪掉傳輸目錄。主機上只執行 `podman image inspect`
  與 `podman save`，從不拉取。壓縮目錄讓尖峰約為「2 × 壓縮後＋1 × 映像」；`podman save | podman load` 的管線約要 3 × 映像
  （podman 先把標準輸入複製成暫存檔，containers/image 又在提交映像前保留每個 blob 的暫存複本）。每個映像之前檢查主機在估計尖峰
  之後仍有 12 GiB＋1 GiB 可用，複製期間每秒檢查一次，降到 12.25 GiB 就停止並刪掉傳輸目錄。實測 OpenDesign 6367 MiB → 壓縮 2359 MiB，
  877 秒（主機負載約 20），過程中主機最低 20.3 GiB 可用。每個映像在 load 之前以 `image_id_range.py` 掃描存下來的各層：有項目的擁有者超出
  appowner 在設備內的巢狀範圍（`/etc/subuid` 的 COUNT）就拒絕，除非 `IMAGES` 表把它標成 `ignore-chown`（目前只有 Nextcloud 的應用映像，見下）。映像 ID 與主機相同（ID 是設定的摘要）；清單摘要會變，所以以摘要固定的參照
  （OpenDesign 的 nginx、code-server 的 ghcr 映像）在套件副本中改成載入後的摘要。
* `opendesign`：套件的 `scripts/install.sh --no-build --accept-defaults --set WOOW_OD_PASEO=on --set OPENDESIGN_PASEO_ORIGIN=https://opendesign.lab.invalid
  --set OD_ALLOWED_ORIGINS=<範例的本機來源>,https://opendesign.lab.invalid`（主機的 `open-design.env` 只有這三個鍵和範例不同：主機開著 Paseo，
  來源是它的公開 https 網址）。`.invalid`（RFC 2606）永遠解析不到；Paseo 連不到中繼，啟動器的監督程式只重啟 Paseo。套件 smoke 56 通過、0 失敗、
  1 個警告（`podman inspect` 看得到 env 型密鑰，套件本身的行為）。**第一次啟動**時 rootless overlay 為 `UserNS=keep-id:uid=1001` 做出整個映像的
  ID 對應複本（約 4 分鐘、約 4.7 GiB），正式主機也有這份複本。
* `nextcloud`（2026-11-23 已安裝一次，見上表）：`~/.config/nextcloud/nextcloud.env` 是範例，資料目錄改成主機目錄項目的 `.local/share/nextcloud-office/{html,data,postgres,redis}`，
  `HOST_BIND` 與 `PHP_MEMORY_LIMIT` 以鍵名從主機的 env 檔讀取（調校值、不是祕密、從不印出），其餘網址、受信任網域與代理設定保留範例的本機值。
  套件會從 Nextcloud 應用商店安裝 richdocuments，dev-e 連不到：改用主機實際執行的版本 12.0.1（主機 2026-11-10 套件備份中的 `appinfo/info.xml`）
  的官方發行檔（應用商店的下載來源，sha256 固定在腳本裡），在第一次啟動前解到 `html/custom_apps`（www-data、0644／0755），安裝程式找得到
  （`app:getpath`）就只會啟用它；`check:nextcloud` 以 `occ integrity:check-app richdocuments` 核對發行檔的簽章（結束碼 0、沒有任何發現）。
  **實驗室專用的差異（ignore-chown）**：`localhost/woow-nextcloud:35.0.1-office2` 有 31348／53616 個項目屬於 65534:65534，全部在
  `/usr/src/nextcloud` 底下（Nextcloud 原始碼的原封副本），超出 appowner 在設備內的巢狀範圍（容器 ID 0–55000；設備本身只有 65536 個 ID），
  所以這個映像的 load 加上 `--storage-opt ignore_chown_errors=true`（和 dev-d 的 Headplane 相同），那些項目在 dev-e 改屬容器的 root；
  映像 ID 仍與主機相同，正式主機照常對應這些 ID。映像自己的 `/entrypoint.sh` 以 `rsync -rlDog --chown $user:$group` 把 `/usr/src/nextcloud/`
  複製到 `/var/www/html/`（第 201、206 行），其餘只讀 `version.php` 與 `config/*.php`（第 182、317–322 行），所以安裝出來的檔案不受影響。
* `code-server`：主機的 env 檔與範例完全相同；主機安裝好的單元另有兩處手動修改（`[Container]` 第一行
  `Environment=WOOW_CONNECTOR_DATA_DIR=/data/pi-agent/connectors-primary`、`Image=` 改成 ghcr 映像的摘要），套件副本在安裝前套用同樣兩處；
  安裝程式的 `--no-build` 檢查要 `localhost/woow-code-server:4.139.1-8`，這個名稱只在安裝期間存在（主機沒有它）。映像 5362 MiB（壓縮 2517 MiB），
  複製 944 秒。`UserNS=keep-id:uid=1000,gid=1000` 的第一次啟動要做整個映像的 ID 對應複本：在 dev-e 實測 318 秒，比單元的
  `TimeoutStartSec=180` 長，所以這個階段在安裝之前先以同樣的對應 `podman create` 一個拋棄式容器做出那份複本（儲存把它留在映像上，容器立刻刪除），
  安裝程式的啟動就不會逾時；裝好的結果和第一次啟動自己做的一樣。安裝程式只有一個預期中的警告（`~/.ssh` 沒有私鑰）。
  和主機比對（`compare_batch2.py code-server`）：只有 `code-server.container` 的 `Image=` 摘要不同（映像 ID 相同），三個 `.volume`、
  `code-server-health.{service,timer}` 相同，env 檔的鍵相同、順序相同。
* `cockpit`：`deploy-src.sh e --src …`（不加示範目錄項目），再執行 `catalog`；`catalog`：已部署應用的主機目錄項目只把 `owner` 改成 appowner、設備金鑰（key-init → key-kit → key-confirm），**不動已安裝的引擎**（匯入那一線可能已部署自己的引擎）；
  `check[:應用]`：引擎 status、目錄項目的健康網址、單元 active、各容器 healthcheck、沒有失敗的使用者單元。

**和正式主機的差異**（`compare_batch2.py` 只讀比對兩邊已安裝的 Quadlet、單元、設定檔、env 檔、目錄項目與每個容器的映像 ID；
值只顯示調校用的鍵，網址與來源一律不顯示；2026-11-23 的結果在 `~/.woowbk-lab/evidence/batch2-lab/compare-prod-opendesign-20261123.txt`）：
OpenDesign 的 7 個 Quadlet 中只有 `open-design-nginx.container` 的 `Image=` 摘要不同；`nginx.conf`、`nginx-auth.conf`、`od-export-bridge.js` 相同，
`nginx-paseo.conf` 只差 Paseo 來源；`open-design.env` 只差 `OD_ALLOWED_ORIGINS`、`OPENDESIGN_PASEO_ORIGIN` 的值（以及鍵的順序）；目錄項目只差 `owner`；
四個容器的映像 ID 都和主機相同。主機另有 `open-design-local-health.{service,timer}`（11-08 加的，套件任何提交都沒有），dev-e 沒有。資料是全新安裝加基準標記。

**基準**（`batch2_baseline.py`，2026-11-23，OpenDesign 12／12 通過，證據 `~/.woowbk-lab/evidence/batch2-lab/20261123T163929-baseline/` 與
`tests/e2e/lab/evidence/batch2-lab-20261123/opendesign-baseline.json`）：標記專案 `woowbk-lab-baseline` 與檔案 `woowbk-lab-baseline.txt`（OpenDesign 自己的 API）、
加密備份 `20261123T084036Z-5ebb7283`（1.0 MB、60.8 秒、停機 22 秒）、之後的標記專案 `woowbk-lab-after`、原位還原（74.8 秒、還原前備份
`20261123T084149Z-1b9c4a80`）：基準標記還在、檔案 sha256 相同、之後的標記消失、健康檢查通過。目前的資料等於這份基準備份。
code-server（2026-11-23 20:12–20:15，16／16 通過，證據 `~/.woowbk-lab/evidence/batch2-lab/20261123T201220-baseline/` 與
`tests/e2e/lab/evidence/batch2-lab-20261123/code-server-baseline.json`）：標記是 IDE 資料卷的程式碼片段、代理資料卷的 pi 技能與工作區
`~/Desktop` 的檔案，和 codeserver-import 那一線測試程式的 `DEVICE_MARKERS` 逐位元組相同（它因此不必自己建立）；加密備份
`20261123T121327Z-74c471c6`（40 KiB、33 秒、停機 9 秒）、之後的標記、原位還原（53 秒、還原前備份 `20261123T121439Z-ad62aa09`）；
備份之前與還原之後各做一次真實登入：`POST /login` 302 加 `code-server-session` cookie，帶 cookie 的 `GET /` 是 302 到
`./?folder=/workspace`、那一頁 200 是工作台，沒有 cookie 的 `GET /` 302 到 `./login`，錯誤密碼拿不到 cookie（第一次嘗試把帶 cookie 的
`GET /` 當成 200 而失敗，只寫入了基準標記；已修正）。
`batch2_baseline.py` 在備份之前與（之後標記建立之前的）還原之前，要求主機在「應用現有資料 × 2.5」的估計尖峰之後仍保有 12 GiB＋1 GiB，
否則該應用記為「PAUSED: host disk」、不寫任何東西；作業執行中主機剩不到 12.25 GiB 就以 `job-cancel` 取消作業。Nextcloud 的基準
（17:12）因此暫停（主機當時 14.2 GiB 可用、估計尖峰 2.7 GiB，備份前就停止）；喚醒後在 21:16–21:40 完成，14／14 通過
（證據 `~/.woowbk-lab/evidence/batch2-lab/20261123T211623-baseline/` 與 `tests/e2e/lab/evidence/batch2-lab-20261123/nextcloud-baseline.json`）：
標記使用者 `woowbk-lab-baseline` 與它的 WebDAV 檔案（`occ user:add`、WebDAV PUT／PROPFIND／GET），加密備份 `20261123T132013Z-34811d90`
（422 MB、停機 102 秒）、之後的標記、原位還原（還原前備份 `20261123T133633Z-a7d7e492`）。驅動程式在還原期間被本線的 590 秒工具時限停掉
（主機負載當時 117–235），還原作業本身照常完成，還原後的 7 項檢查由同樣檢查的接續腳本完成（證據裡有記錄）；更早一次嘗試因驅動程式
用錯密碼寫入之後的檔案（HTTP 401）而停止，已修正，它的備份已刪除。

**輪替與主機限制**（2026-11-23 實測）：三個應用的映像 15.2 GiB，加上 OpenDesign 與 code-server 第一次啟動時的 keep-id 複本（6.2＋5.2 GiB），
一共約 27 GiB；主機在保留 12 GiB 之後只剩約 16 GiB，記憶體約 2.3 GB 可用。所以 dev-e 一次只部署（與執行）一個應用，測完以
`deploy-batch2.sh e drop-images:<應用>` 與移除該應用後換下一個。另外，主機使用者的 inotify 實例上限只有 128（`fs.inotify.max_user_instances`），
rootless 容器（含巢狀）的用量全部算到同一個使用者，16:35 只剩 2 個；dev-e 的 `systemd-ask-password-wall.path` 因此以「Too many open files」
失敗，`verify-device.sh e` 因而報 degraded；之後把設備內沒有用的 `systemd-ask-password-{console,wall}.path` 遮蔽了（各佔一個實例）。
擁有者同意後，main 在 17:13 把上限調到 1024（`/etc/sysctl.d/90-woowtech-inotify.conf`）。規則（main，16:55）：dev-e 每加一個應用或容器之前跑一次**有上限的探測**（最多同時建立 10 個
實例、立即釋放），可用少於 5 個就暫停；不留下 `tail -f` 之類的追蹤程式或閒置的測試容器。dev-e 只由 batch2-lab 變更，其他線在
`team/batch2-lab.md` 寫 `REQUEST:` 並等 READY。

**輪替指令**（2026-11-23 第 3 輪加入，離線測試 9 項＋6 個突變檢查）：先以 `batch2_baseline.py --verify <應用>` 證明資料回到基準，再
`flock -w 3600 /tmp/woowbk-dev-e-mutation.lock tests/e2e/lab/deploy-batch2.sh e rotate:<應用>`：依序停止該應用的單元與計時器，每一個都不再
執行（inactive；健康檢查單元上次失敗算 failed、也不在執行）、沒有它的容器，才刪除它的映像（keep-id 複本隨映像一起刪）；任何一項不符就停下、
映像保留。資料、單元、env、密鑰、目錄項目與基準備份都留著。喚醒用 `deploy-batch2.sh e wake:<應用>`：`images:<應用>`、確認每個已安裝單元的
`Image=` 都已載入（否則不啟動任何東西）、code-server 先做 ID 對應複本、有上限的 inotify 探測（少於 5 個就停）、主機在第一次啟動的複本
（OpenDesign 7 GiB、Nextcloud 3 GiB）之後仍要留 13 GiB，依序啟動單元（啟動時主機低於 12.25 GiB 就把該單元停掉）、健康網址回應後才啟動計時器，
最後在 `WAKE_READY_S`（預設 1200 秒）內 `check:<應用>` 通過。磁碟需求（`images` 的守門：映像大小的 2.2 倍＋13 GiB）：code-server 喚醒開始時約需 24.5 GiB 可用、用掉約 10.6 GiB；
OpenDesign 約需 26.7 GiB、用掉約 12.1 GiB；Nextcloud 約需 17 GiB、用掉約 6.1 GiB。

**重設**：`tests/e2e/lab/reset.sh e --up` 刪除容器與三個資料卷，再照「建置」重跑。新的設備金鑰會覆寫 `dev-e-kit.txt`；`dev-e-markers.json` 保留。
dev-e 的變更請以 `flock -w 3600 /tmp/woowbk-dev-e-mutation.lock <指令>` 包起來（與 dev-d 相同的規則）。

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
| `h7` | `/opt/woow-cockpit-src` 的 `manage.py plan/install/verify` → 回退最新交易 → 繼續回退到備份套件被移除（helper、頁面、目錄設定都不在）→ 重新安裝；每一步比對 `/var/lib/woowtech-backup` 與金鑰目錄的內容雜湊。2026.11.17.1 起另檢查排程備份的計時器（唯讀：`systemctl show`、單元檔、`timers.target.wants` 連結）：安裝後 enabled／active、`plan` 與 already-current 的 `install` 沒有 systemctl 步驟、`verify` 回報計時器；回退新增單元的那筆交易時步驟為 stop、disable、daemon-reload，單元檔、連結與它建立的單元目錄都移除、systemd 不再載入計時器、`verify` 不再有 timer；重新安裝時為 daemon-reload、enable --now，交易紀錄的 `systemd.before` 是「未載入」；只更新套件的交易回退後計時器回到交易前的狀態 |
| `sec1` | 審查發現 SEC-1 的實機版：先做對照組，證明設備上真正的 podman 4.9.3 會照做（appowner 以裸 `podman volume import` 與 `podman load` 匯入「絕對路徑符號連結＋其下的成員」的 tar，成員確實被寫進家目錄中的標記目錄，之後刪除）。接著在 dev-a **設備內**用設備金鑰解開一份新的含映像備份（串流到 `/var/tmp/woowbk-sec1-work`，明文在離開前刪除），在資料卷 tar 與應用映像的 OCI 封存**所有真實成員之後**各加上指向 `~/.config/systemd/user`、`~/.config/containers` 的絕對符號連結與其下的成員，修正 manifest 的大小與 sha256，以設備公鑰重新加密（主機只拿到密文）；並以已安裝引擎的 `nested` 檢查記錄原始項目通過、改造項目被拒的原因。經真正的 bridge 上傳 → upload-finish → inspect → 驗證作業 → 原位還原作業：還原必須在 preflight 失敗（safety、stop 未執行），錯誤分別點名容器映像與資料卷；期間 appowner 的 podman 沒有任何 image／volume 事件（沒有 load、tag、volume create/remove/import）、變更檔案掃描乾淨、整台設備找不到 `woowbk-sec1` 路徑、家目錄設定與應用資料、部署檔、映像名稱不變、沒有還原前備份。2026-11-13 起深入驗證作業以 `corrupt-archive` 拒絕，索引記錄 `verified {ok: false, deep: true}`（先前只檢查外層封存、回報完整）；格式 2 的基礎備份以已安裝引擎的 `ArchiveWriter` 重新封裝 |
| `fidelity` | 合法資料的保真度：在 dev-a 應用資料卷的 `woowbk-fidelity/`（應用不計數）以 `podman unshare` 建立絕對／相對／懸空符號連結、硬連結、超過 100 bytes 的名稱與超過 255 bytes 的路徑、空目錄、setgid 與 sticky 目錄、user.* 延伸屬性、非 UTF-8 檔名、中文檔名、FIFO、不同擁有者（70、1000、33、54999）、唯讀與可執行檔、次秒 mtime；以**應用容器內**（`podman exec`）看到的完整清單（類型、容器內 uid/gid、權限、大小、mtime、連結目標、sha256、延伸屬性、硬連結群組）為準。含映像備份 → 修改探測目錄 → 原位還原 → 清單必須相同；再下載 → dev-b 重設 → 上傳 → 全新部署還原（緊急金鑰）→ dev-b 容器內清單必須相同（只有次秒 mtime 因 tar 只存整秒而不同）。結束時刪除探測目錄與測試備份 |
| `fresh` | dev-b 全新部署還原：(1) 預先存在同名的應用機密、設定檔、資料卷或資料庫資料卷（各自單獨測）→ inspect 與還原作業都在 preflight 拒絕，什麼都沒有刪除或建立；(2) 另建無關的資料卷、機密、設定檔、網路與映像名稱，並讓 `localhost/woowbk-demo-app:1` 先指向探測映像；還原在 `start` 階段被 SIGKILL（範本、遮蔽、機密、設定檔、資料卷都已建立）→ 復原移除整個部署、無關物件不變；已載入的映像名稱照 CONTRACT §8 保留；(3) 以一次性的資料庫 drop-in 讓還原在破壞性步驟後失敗 → 程序內自動回復 → `remove_fresh` 把映像名稱改回原本的探測映像（retag），或移除這次新增的名稱（untag），無關物件不變。最後再做一次全新部署還原，資料等於來源備份 |
| `leaks` | 兩台設備的作業紀錄、日誌、索引、requests、journal 沒有應用密鑰或 age 金鑰；沒有 `key-*`、staging、孤兒封存檔；主機 hardening／integration 證據沒有金鑰 |
| `upload_window.mjs [MiB=2,4] [次數=3] [chunkKiB=64,256,512]` | H8：以 Playwright 攔截 `backup.js`，只在測試瀏覽器內改 `WINDOW_SIZE` 與 `CHUNK_SIZE` 並加上計時；經 cockpit-ws 上傳約 142 MB 到 dev-b，核對 sha256，停在金鑰步驟後刪除。程式庫與設備上的預設值（4 MiB 視窗、512 KiB 訊框）不變 |

`H1_CASES`、`H3_FAULTS`、`H4_KILLS`、`H5_PHASE`、`H6_FILES`、`H7_FULL=0`、`H2_TMPFS` 環境變數可只跑一部分。
格式 2 的 `unknown-app`：只讀被選應用的封存檔，還原 woowbk-demo 時在「解密並驗證檔案」就以 `incompatible` 拒絕（格式 1 在預檢）。`h7` 期待設備是 `deploy-src.sh` 剛安裝的狀態：若 woowbk-demo 的目錄項目已由「應用設定」（`catalog-install`）改過，`manage.py plan` 會列出它、回退也會拒絕（檔案在安裝後被變更）；`h7` 會先把 manage.py 管理的夾具內容放回，結束時再以 `catalog-install` 裝回管理者的版本。dev-a 的安裝交易紀錄中有一筆在 2026-11-13 被實驗室專用的 archive.py 修補改過（引擎核心角色的 E1–E3 暫時修補），所以完整回退鏈（`H7_FULL=1`）會在那一筆被 `manage.py` 正確拒絕（「Changed since installation」）；2026-11-14 整合輪以 `H7_FULL=0` 在一組乾淨的交易（先部署舊版再部署工作樹）上驗證。2026.11.17.1 起，`h7` 比對 `/var/lib/woowtech-backup` 的指紋時排程必須沒有到期的時段（關閉或沒有設定檔，例如 `schedule_e2e.py cleanup` 之後）：計時器每 5 分鐘的檢查只碰 `/run`，但開始的排程備份會寫入狀態檔與作業紀錄。2026-11-17 以 `H7_FULL=0` 在剛由 c393dfb 部署工作樹的 dev-a 上 23／23 通過（回退的就是新增單元的那筆交易；第二輪 ad7858e 先以安裝程式的回退回到 2026.11.15.2 再部署，結果相同）。

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
無法驗證、確認步驟需要額外勾選、還原成功且摘要一致；設定改回）、`cleanup-lab`（刪除頁面建立的備份與未加密副本）。順序：`catalog` 在 `strengthen_e2e.py catalog-apply` 之前（或先以 `deploy-src.sh a` 與 `dirs-catalog.sh a install` 換回夾具），`devb` 在 `catalog-apply` 之後（需要 dev-b 產生的資料摘要項目）；`cleanup` 假設 woowbk-demo 的手動備份都只含這個應用（候選數 = 手動份數 − 5），`ui_e2e.mjs s1` 在建立頁保留全選，會留下一份含所有應用、不會成為候選的備份，在它之後執行時先刪除那份測試備份（2026-11-17 第二輪因此第一次 9／10，重跑 11／11）。

### 資料摘要 SQL 探測（digest_sql_probe.py，2026-11-14 審查修正）

`python3 -I tests/e2e/lab/digest_sql_probe.py [證據目錄]`：以 labpodman 啟動一次性的 `postgres:16-alpine`（`--memory 384m`），
用引擎自己的 `woowbackup.digests` SQL（與 adapter 相同的 `psql -f -`、`PGOPTIONS`、`PGCLIENTENCODING=UTF8`）檢查：
非超級使用者的資料表擁有者定義 `CREATE CAST (victim AS text) WITH FUNCTION evil(victim)`（函式以 `COPY … TO PROGRAM`
寫一個標記檔）——修正前的 `t::text` 會以超級使用者身分執行它（標記檔內容 `postgres super=true`），引擎的 SQL 不會（H1）；
沒有自訂轉換、沒有 `t` 欄位的資料表，摘要與修正前完全相同；有名為 `t` 的欄位時，其他欄位改變摘要也會改變（F2）；
SQL_ASCII 資料庫中 0x80 以上的位元組、LATIN1 資料庫的非 ASCII 資料表名稱（與 UTF-8 資料庫的相同內容摘要相同；F6）。
結束時移除容器，結果寫入 `digest-sql-probe.json`。

## 排程備份情境（schedule_e2e.py，2026.11.17.1）

`python3 -I tests/e2e/lab/schedule_e2e.py <install|timer|fast|busy|timezone|run-now|retention|partial|kit-gate|compat|noise|reboot|cleanup|all>`，
證據寫入 `~/.woowbk-lab/evidence/schedule/<時間>-<情境>/`（`driver.log`、`result.json`、作業紀錄、journal 行、
`systemctl show`／`cat` 的輸出），建立的備份與還沒復原的實驗室變更記在同目錄的 `state.json`，由 `cleanup` 收尾。呼叫方式與
`cli_e2e.py` 相同（已安裝的 helper、root、stdin JSON；下載／上傳走設備內真正的 `cockpit-bridge`）；設備內的其他指令一律直接以
argv 執行（`labpodman exec <設備> <指令…>`，或以標準輸入交給 `python3 -I -` 的程式），不經過 shell。觸發也是真的：systemd 依
`woowtech-cockpit-backup-schedule.timer` 在每個 5 分鐘整點啟動 `woowtech-cockpit-backup-schedule.service`，或以
`systemctl start` 立即做一次檢查。**不要對設備執行 `systemd-analyze verify`**（曾取代執行中管理器的 socket），單元只以
`systemctl show`／`systemctl cat` 檢查。

讓時段立刻到期（不等到 03:00）：root 直接寫 `/etc/woowtech-cockpit/backup/schedule.json`（root 0644、剛好是文件列出的欄位），
`time` 為設備時間最近一個已過的 5 分鐘整點（不到 15 分鐘前），`armed_at` 為它的前一分鐘，再 `systemctl start` 檢查服務。不需要
立刻到期的地方走頁面的路徑（`schedule-set`），時間選今天已經過去、早於 `armed_at` 的時段，所以明天之前不會執行。同一個時段只會
處理一次（`schedule-state.json` 的 `handled`），所以每個以檢查觸發的情境要等到下一個整點（最多 5 分鐘）。

前置條件：兩台設備執行中（`labpodman start`）、woowbk-demo 在兩台都執行中、dev-a 有設備金鑰且緊急金鑰已確認
（`~/.woowbk-lab/secrets/dev-a-kit.txt`）、dev-b 沒有設備金鑰（`kit-gate` 在 dev-b 建立實驗室金鑰，`cleanup` 移除）、主機可用
記憶體 ≥ 1200 MB；`install` 最先執行（它執行 `deploy-src.sh a`、`b`）。`all` 依序執行 install、timer、fast、busy、timezone、
run-now、retention、partial、kit-gate、compat、noise、reboot、cleanup。安裝器的回退與重新安裝（計時器的停用與再啟用）在
`hardening.py h7`。

| 情境 | 內容 |
| --- | --- |
| `install` | 兩台設備各執行 `deploy-src.sh`：從沒有計時器的 2026.11.15.2 安裝時，`manage.py install` 的步驟是 `daemon-reload`、`enable --now <timer>`（沒在執行，不先 stop），交易紀錄的 `systemd.before` 是安裝前的狀態（not-found、`stopped: false`）；已是最新時為 `already-current` 並回報計時器。`systemctl show`：計時器由 `/usr/local/lib/systemd/system/` 載入、enabled、active、`OnCalendar=*-*-* *:00/5:00`、`AccuracyUSec=15s`、`Persistent=no`、啟動 tick 服務、`WantedBy=timers.target`、下一次在 5 分鐘內的整點；服務為 oneshot、固定 argv `…/woowtech-cockpit-backup schedule-tick`、stdin／stdout 為 null、stderr 到 journal、`SyslogLevel=4`（warning）、`LogLevelMax=5`（notice）、`TimeoutStartUSec=15min`；`systemctl cat` 與來源的單元檔逐字相同（含 `ConditionPathExists=`），檔案 root:root 0644、sha256 相同、`timers.target.wants` 有連結；`manage.py verify` 為 verified 並回報計時器（不算漂移），之後的 `plan` 沒有變更也沒有 systemctl 步驟；已安裝的引擎、helper、VERSION 與工作樹逐檔相同；`schedule-get` 看到計時器 enabled／active、排程預設關閉。從舊的工作樹升級時步驟為 stop、（單元檔有變才）daemon-reload、enable --now，交易紀錄 `stopped: true`。dev-a 另測遮蔽的計時器（`systemctl stop` + `systemctl mask`）：安裝仍完成（already-current）、沒有 systemctl 步驟、`notices` 說明它被保留為遮蔽、`plan` 也說明且不規劃步驟、引擎看到 not enabled／not active；`systemctl unmask` 後下一次安裝 `enable --now`、計時器恢復執行 |
| `timer` | dev-a：`schedule-set` 預覽（不寫檔、下一次正是目標整點、不刪任何備份）→ 確認（root 0644、只有文件列出的欄位、`armed_at` 為現在、journal `schedule-set … previous_enabled=false`）→ 不手動觸發，等計時器：服務在整點後 15 秒內啟動、作業由這次檢查建立（request id `schedule-<UTC 時段>`）、參數是手動備份的參數加 `schedule{slot, trigger: on-time, keep_last}`、備註「排程備份」，結果 `scheduled`、不是部分完成、有加密；`list` 顯示「排程」；journal 一行 `schedule-run`；下一次是明天同一時間。另外重現安裝剛完成的狀態（`systemctl restart` 計時器並刪除檢查標記：計時器剛啟動、還沒檢查過）：`last_tick_age` 為 null、`active_age` 不到一分鐘，`schedule-get` 與 `status.schedule` 都沒有提醒（第一輪發現的誤報，已修正） |
| `fast` | dev-a：另一個檢查持有 `schedule-tick.lock` 時，手動檢查回傳 `tick-running`、服務仍然成功；寫入到期的時段後 `systemctl start` 兩次、再手動檢查一次 → 這個時段只有一個作業（後兩次是 `idle`）；作業與結果同上；`inspect`：封存本身是 `manual`、備註「排程備份」（格式不變）；`schedule-state.json` root 0600、登記表 `{job, slot, trigger}`、`handled`；作業結束後的檢查記錄結果，journal 對這個時段只有 `schedule-run`、`schedule-result` 各一行（notice）；`schedule-get` 與 `status.schedule` 的上次執行（含設備時間的 `started_local`／`finished_local`）、下次執行、時區、計時器，`schedule.defaults` 為 false（顯示的是儲存的設定）；各應用用量把它算在 `types.scheduled`；備份刪除後，下一次檢查移除它的登記 |
| `busy` | dev-a：先開始驗證作業（最大的實驗室備份，深入驗證約 15 秒），以 SIGSTOP 暫停它的作業單元（紀錄仍是 running），檢查遇到 `busy` → 時段等待（`waiting {slot, local, since, job_id}`、事件 `waiting`（`local` 為設備時間）、`status.schedule.waiting`、`jobs.schedule_events`、journal `schedule-wait … busy_job=<驗證作業>`）；仍在執行時再檢查一次：`busy`、trigger `late`、沒有第二筆事件；SIGCONT 讓驗證完成後，下一次檢查以 `late` 開始這個時段、不再等待 |
| `timezone` | dev-a：Etc/UTC 下 03:00 的下一次是 `03:00:00Z`；`/etc/localtime` 改連到 Asia/Taipei 後，下一個指令就用新時區（`+08:00`、台北 03:00 = 前一天 19:00Z）；呼叫端的 `TZ=America/New_York` 被忽略；以台北時間寫入到期的時段（同一個 HH:MM 以 UTC 看還沒到）→ 下一次檢查就開始這個時段，上次執行的 `started_local`／`finished_local` 是台北時間；再改連 America/New_York（11 月 `-05:00`）；最後連回原本的時區 |
| `run-now` | dev-a：沒有儲存的設定時 `schedule-get` 顯示預設值（`defaults: true`、`saved: false`），`run-now` → `invalid-request`（reason `not-saved`）；嚴格的請求檢查；`schedule-tick` 只看 argv（標準輸入不讀，多一個參數就是 `invalid-request`）；`schedule.json` 被改成群組可寫 → 顯示給設備擁有者看的問題（「排程備份的設定檔權限不安全（必須只有系統管理員能修改），排程備份已暫停。請通知工程人員檢查。」，不寫檔名）與預設值（`defaults: true`）、`run-now` 以 reason `settings-problem` 與同一段文字拒絕、兩次檢查只記一筆 `settings-problem` 事件與一行 warning、注意事項 `settings-problem`；權限改回後問題消失、顯示儲存的設定；排程關閉時 `run-now` 照樣執行，相同 request id 去重、執行中另一個請求 `busy`（`details.job_id`）；`slot` null、trigger `run-now`、算作排程備份；journal `schedule-run slot=-` 與 `schedule-result slot=-` 各一行 |
| `retention` | dev-a：手動保留原則設為「woowbk-demo 保留最新 K+2 份」（K 為現有的手動備份份數，先預覽確認不會刪除任何既有備份），排程保留 2 份，依序 S1（排程）、M1（手動）、S2、S3、M2：只有 S3 刪除了東西，就是最舊的排程備份 S1；手動備份一份都沒刪（若排程備份被算進手動原則，M2 會刪掉兩份最舊的手動備份）；S2 之後的 `schedule-set` 預覽正好列出 S1；`retention-plan` 沒有候選、用量為手動 K+2、排程 2；journal 只有一行 `retention-delete backup=<S1> … reason=schedule`；最後原則改回、測試備份刪除 |
| `partial` | dev-a：(a) 擁有者停止 woowbk-demo 的兩個單元（狀態「已停止」、沒有 `problems`），排程 apps 為 `"all"`，立即執行一次 → 部分完成、略過 woowbk-demo（原因「應用「示範筆記應用」已停止，無法備份：備份時它的資料庫必須在執行中。」）、其他應用照常備份；(b) 排程列出 woowbk-demo 與 woowbk-dirs，woowbk-dirs 的目錄項目暫時移到 `/root/woowbk-schedule-lab/`（之後放回並比對 sha256）→ 部分完成，原因「此設備沒有設定應用 woowbk-dirs。」。兩者都檢查下一次檢查記錄的 `partial` 事件、`status.schedule.attention`（「部分完成：上次排程備份沒有包含「…」。…」）、journal 的 warning `schedule-result … result=partial … skipped=<id>`、列表中的備份不含被略過的應用 |
| `kit-gate` | dev-b（沒有設備金鑰）：`gate` 為 `no-device-key`，開啟（預覽與確認）都是 `no-device-key` 且不寫檔；儲存關閉的設定不受限制；`run-now` 也是 `no-device-key`；「預設加密備份」關閉時不需要金鑰；`key-init` 建立實驗室金鑰後 `gate` 為 `kit-unconfirmed`，開啟被拒（`invalid-request`、reason `kit-unconfirmed`、field `schedule.enabled`、「開啟排程備份前，請先保存緊急金鑰。」）、`schedule.json` 不變；這時 `run-now` 可以執行（和手動備份一樣不受緊急金鑰限制）；`key-kit` → `key-confirm` 之後可以開啟（journal `schedule-set enabled=true … previous_enabled=false`），再關閉。緊急金鑰內容不保存 |
| `compat` | 需要 `kit-gate` 的結果。dev-a 的排程備份經 bridge 下載；上傳回 dev-a 時回傳原本的紀錄（仍是排程備份）。dev-b 以安裝程式自己的回退（文件記載的降級方式）回到 c393dfb：回退步驟為 stop、disable、daemon-reload，單元檔、`timers.target.wants` 連結與安裝時建立的單元目錄都移除，引擎與 c393dfb 逐檔相同（2026.11.15.2）。舊引擎在新檔案（`schedule.json`、`schedule-state.json`）與新作業紀錄存在時：`status`、`jobs`（排程作業列為備份作業）、`job-status` 都正常；dev-b 自己的排程備份列為手動備份、備註「排程備份」、可以 `inspect`。dev-a 的排程備份上傳到舊引擎 → `uploaded`、沒有金鑰時 `key-required`、以 dev-a 的緊急金鑰 `inspect`（manual、排程備份、來源 woowbk-dev-a、可原位還原）→ 原位還原成功、資料核對一致、dev-b 的資料等於 dev-a 備份時。之後 `deploy-src.sh b` 回到工作樹（daemon-reload、enable --now）：dev-b 自己的那份又是「排程」，上傳的那份是 `uploaded`、不是排程；保留 1 份的預覽只會刪除 dev-b 自己的排程備份 |
| `noise` | dev-a：排程關閉時 3 次 `systemctl start` 加上 2 次計時器的檢查，以 `journalctl _PID=1` 計算 PID 1 對 tick 服務寫的行；對照組是兩個暫時單元（`systemd-run`，一個沒有、一個有 `LogLevelMax=notice`） |
| `reboot` | dev-a（選用；先刪除登記表已空的狀態檔，模擬從沒處理過時段的設備）：(1) 最近的時段在 22 小時前、下一個在 2 小時後，共 3 天 → `missed`、一筆合併事件（count 3、first／slot）、注意事項 `missed`、journal 一行 `schedule-missed`、沒有作業；事件帶設備時間的 `local`／`first_local`；(2) 35 分鐘前、沒有檢查看到的時段 → 下一次檢查前為 `overdue`；停止計時器（「設備關機」）→ `timer-inactive`（`active_age` null）；(3) 在整點前 40 秒 `labpodman restart`：計時器自己回來（enabled），引擎的開機時間（PID 1 啟動後的秒數）從零開始，這時沒有「排程檢查沒有在執行」（計時器剛啟動），時段仍是 `overdue`；PID 1 未滿 10 分鐘時的檢查（手動一次、計時器約 1 與 6 分鐘時各一次）都是 `settle`：不補做、什麼都不記錄、沒有作業；PID 1 滿 10 分鐘後計時器的第一次檢查以 `catch-up` 補做這個時段（作業在 PID 1 滿 10 分鐘後建立），重新開機後的 journal 只有它的 `schedule-run` 與 `schedule-result` 各一行 |
| `cleanup` | 復原中途停止的情境留下的變更（時區、移走的目錄項目、停止的示範應用、保留原則）；兩台設備的排程關閉、本驅動程式建立的備份刪除、`schedule.json` 與 `schedule-state.json` 刪除（登記表已空時）；woowbk-demo 目錄項目換回夾具；移除 dev-b 的實驗室金鑰（只刪 `kit-gate` 新增的 `device-<id>.key` 與 `keys.json`），確認 dev-b 沒有設備金鑰；刪除下載的備份檔；證據不含金鑰 |

2026-11-17 實測。第一輪（c455a07 加上這個驅動程式，兩台設備由 2026.11.15.2 安裝工作樹）找到兩個產品問題，都在 ad7858e 修正：
已停止的應用（兩個單元都停止、`status` 為「已停止」、沒有 `problems`）讓整次排程備份在「檢查空間與應用」以「無法讀取資料庫 main
的大小…」失敗、其他應用也沒有備份（現在以 `Adapter.unavailable` 略過、部分完成）；安裝程式 `enable --now` 之後、第一次檢查以前，
開機已久的設備會誤報「排程檢查沒有在執行」（現在也看計時器啟動的時間 `active_age`）。第一輪其他結果：`timer` 16／17、`partial`
12／13（未通過的就是這兩項），其餘與第二輪相同的情境全部通過。

第二輪（ad7858e：上述修正、以 PID 1 計算開機時間、設備時間的 `local` 文字、`schedule.defaults`、不寫檔名的問題說明、tick 服務的
`StandardError=journal`、遮蔽的計時器）：dev-a 先以安裝程式的回退回到 2026.11.15.2 再 `deploy-src.sh a`（新增單元的交易），dev-b
從第一輪的工作樹升級。`install` 29／29（dev-a daemon-reload、enable --now，遮蔽的計時器保留遮蔽、解除後 enable --now；dev-b
stop、daemon-reload（服務單元有變）、enable --now）、`hardening.py h7`（`H7_FULL=0`）23／23、`timer` 17／17、`fast` 20／20、
`busy` 15／15、`timezone` 15／15、`run-now` 19／19、`retention` 11／11、`partial` 19／19、`kit-gate` 20／20、`compat` 31／31、
`noise` 7／7、`reboot` 24／24（重新開機後 PID 1 為 36 秒與 342 秒時的計時器檢查都是 settle、時段仍逾期，642 秒時補做）、
`cleanup` 13／13。`noise` 兩輪結果相同：3 次 `systemctl start` 與 2 次計時器檢查，systemd 255 對 tick 服務沒有寫任何 PID 1 行
（`LogLevelMax=notice` 也過濾 PID 1 對這個單元的 info 訊息）；沒有 `LogLevelMax` 的對照單元每次 3 行（Starting…、Deactivated
successfully.、Finished…，priority 6），有 `LogLevelMax=notice` 的對照單元 0 行；沒有事的檢查也不寫引擎的行。排程作業本身的
`woowtech-backup-<作業>.service` 照常有 PID 1 的行（每個時段一次）。

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
* **開機時間（排程備份）**：設備容器沿用主機核心的時間命名空間（`/proc/self/ns/time` 與主機相同），所以設備內的
  `/proc/uptime` 與 `CLOCK_BOOTTIME` 都是**主機**的開機時間（2026-11-17 實測約 17.6 天），`labpodman restart` 之後也一樣。
  引擎自 ad7858e 起以 PID 1 啟動後的秒數為開機時間（`CLOCK_BOOTTIME` 減去 `/proc/1/stat` 的啟動時間），容器重新啟動後會從零開始，
  所以「開機 10 分鐘內不執行排程」可以用 `labpodman restart` 實測（`schedule_e2e.py reboot`）。第一輪（引擎還用 `CLOCK_BOOTTIME`）
  時重新開機後立即補做，這一點只能在時間命名空間中證明（util-linux 2.39.3 的 `unshare --boottime` 不能解析負數，要用 Python
  寫 `/proc/self/timens_offsets`）。
* **讓作業保持執行中**：`systemctl kill --signal=SIGSTOP woowtech-backup-<作業>.service` 暫停整個作業單元（紀錄仍是 running、
  單元仍是 active），`--signal=SIGCONT` 繼續；`schedule_e2e.py busy` 以此讓兩次檢查都遇到同一個驗證作業。
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
