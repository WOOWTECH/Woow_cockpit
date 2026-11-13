# woowbk-dirs：主機資料夾備份與還原示範應用（測試夾具）

`woowbk-dirs` 是「備份與還原」**主機資料夾**（目錄項目 `data_dirs`）功能的測試夾具，不是產品功能。它模仿正式主機上
Nextcloud 與 Home Assistant 的部署形態：應用資料與 PostgreSQL 資料目錄都放在應用擁有者家目錄中的資料夾，以
bind mount（Quadlet 的 `Volume=%h/<資料夾>:<容器內路徑>`）掛進容器，並由**非 root 的容器帳號**寫入，所以主機上的
檔案屬於擁有者的 subuid。資料庫採**冷備份**：目錄項目不列 `postgres`，資料庫服務也列在 `writer_units`，備份時一起
停止，整個資料目錄（含角色、密碼、擁有者與權限）以檔案層級備份與還原。

所有名稱都以 `woowbk-` 開頭，只部署在實驗室設備（`tests/e2e/lab/`）。不可用來測試正式應用的資料。

## 組成

| 項目 | 名稱 | 說明 |
| --- | --- | --- |
| 受信任目錄設定 | `catalog.json` | 安裝為 `/etc/woowtech-cockpit/backup/apps/woowbk-dirs.json`（root 0644），由 `tests/e2e/lab/dirs-catalog.sh <a\|b> install` 安裝 |
| Quadlet 範本 | `quadlet/woowbk-dirs.network`、`woowbk-dirs-db.container`、`woowbk-dirs-app.container` | 安裝為 `/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-dirs/quadlet/`（root 0644）；部署時複製到 `~appowner/.config/containers/systemd/` |
| 使用者服務 | `woowbk-dirs-network.service`、`woowbk-dirs-db.service`、`woowbk-dirs-app.service` | 由 Quadlet 產生；`WantedBy=default.target`，搭配 linger 開機自動啟動 |
| 網路 | `woowbk-dirs` | 容器以名稱互相解析 |
| 資料庫容器 | `woowbk-dirs-db` | `docker.io/library/postgres:16-alpine`，**以容器內 UID 70（postgres）執行**（`User=70:70`），資料目錄是主機資料夾 `~/.local/share/woowbk-dirs/postgres`（容器內 `/var/lib/postgresql/data`）；`--stop-timeout 60` 讓資料庫正常關閉；`--memory 256m` |
| 應用容器 | `woowbk-dirs-app` | `localhost/woowbk-dirs-app:1`（`app/Containerfile`：python:3.12-alpine + pg8000 1.31.2，標準函式庫 HTTP）；**以容器內 UID 33 執行**（`User=33:33`，Debian 的 www-data，如 Nextcloud）；主機資料夾 `~/woowbk-dirs/data` 掛在 `/srv/data`；`127.0.0.1:18091→8080`；`--memory 128m` |
| 主機資料夾 | `.local/share/woowbk-dirs/postgres`、`woowbk-dirs/data`（相對於擁有者家目錄） | 目錄項目的 `data_dirs`；見下節 |
| 密鑰 | `woowbk-dirs-db-password`、`woowbk-dirs-role-password`、`woowbk-dirs-app-key` | 以 `podman secret create NAME -` 由標準輸入建立；超級使用者 `dirs` 的初始密碼（只在建立資料庫叢集時使用）、應用自己的資料庫帳號 `dirs_app` 的密碼（如 Nextcloud 的 oc_admin）、項目簽章的 HMAC 金鑰 |
| 設定檔 | `~/.config/woowbk-dirs/app.env`（0600，目錄 0700） | `APP_TITLE=…`，以 `EnvironmentFile=` 載入 |

Quadlet 刻意**不使用** `:U` 等會在啟動時修正擁有者的選項：擁有者與權限必須由還原帶回，不能被啟動程序悄悄修好。
PostgreSQL 的資料目錄只要擁有者或權限不對（必須是容器內 UID 70、0700），資料庫就拒絕啟動，還原的健康檢查不會通過。

應用映像只存在於建置它的設備（`localhost/…` 無法下載）；跨設備還原需要包含映像的備份。

## 主機資料夾與擁有者

容器內看到的擁有者（UID／GID），以及在主機上（應用擁有者的 rootless 使用者命名空間之外）看到的擁有者：

| 路徑（相對於擁有者家目錄） | 權限 | 容器內擁有者 | 主機上的擁有者 |
| --- | --- | --- | --- |
| `.local/share/woowbk-dirs/postgres/` 與其中所有檔案 | 目錄 0700、檔案 0600 | 70:70（postgres） | subuid：`起點 + 70 − 1` |
| `woowbk-dirs/`（上層資料夾，不在 `data_dirs` 中） | 0750 | — | 擁有者本人 |
| `woowbk-dirs/data/`（掛在 `/srv/data`） | 0755 | 0:0（容器內 root） | 擁有者本人 |
| `data/README.txt`（`user.woowbk.role` 延伸屬性）、`data/.storage/core.json`、空資料夾 `data/.storage/empty/`、`data/共享/說明 文件.txt`（中文與空白檔名）、`data/共享/唯讀.txt`（0444） | 0644／0755／0444 | 0:0 | 擁有者本人（如 Home Assistant 的設定資料夾） |
| `data/www/` 與其下所有項目 | 目錄 0750、檔案 0640 | 33:33（應用） | subuid：`起點 + 33 − 1` |
| `data/www/docs/<xx>/<yy>/<id>-<名稱>.txt` | 0640 | 33:33 | 兩層巢狀資料夾；每個檔案有 `user.woowbk.item` 延伸屬性 |
| `data/www/archive/<id>-<名稱>.txt` | 0640 | 33:33 | 對應 docs 檔案的**硬連結** |
| `data/www/latest` | — | 33:33 | 指向最新 docs 檔案的**相對符號連結** |
| `data/www/db/app.sqlite`、`app.sqlite-wal`、`app.sqlite-shm` | 0600 | 33:33 | SQLite，**WAL 模式**；應用關閉自動 checkpoint 並在結束時不關閉連線，已提交的資料留在 `-wal` 檔中，還原必須把兩個檔案一起帶回 |
| `data/www/tmp/` | 0700 | 33:33 | 空資料夾 |

subuid 的換算以擁有者的 `podman unshare cat /proc/self/uid_map` 為準（實驗室：容器內 1–55000 對應到 `/etc/subuid`
的起點開始的 55000 個 ID）。dev-a 是 `appowner:10000:55000`（UID 33 → 10032、70 → 10069）；dev-b 以
`tests/e2e/lab/subids.sh b 10500:55000 --reset-storage` 設成不同的範圍（33 → 10532、70 → 10569），跨設備還原才能
證明擁有者是依目標設備的命名空間重新對應，而不是照抄主機上的數字。

## 資料庫（冷備份）

* 叢集由官方映像的進入程式在空的資料目錄中建立：超級使用者 `dirs`、資料庫 `dirs`，密碼來自
  `woowbk-dirs-db-password`（`type=env`）。
* `tools/seed.py` 第一次部署時以超級使用者透過容器內本機 socket（SQL 走標準輸入）建立：
  角色 `dirs_app`（LOGIN；密碼是 `woowbk-dirs-role-password`，以用戶端算好的 SCRAM-SHA-256 驗證碼設定，明碼不送到
  伺服器也不進記錄）、`GRANT USAGE, CREATE ON SCHEMA public TO dirs_app`、資料庫 `dirs_audit OWNER dirs_app`。
* 應用一律以 `dirs_app` 連線（TCP、SCRAM）：資料表 `dirs.items`（由 `dirs_app` 擁有）與 `dirs_audit.events`。
* 角色、密碼、擁有者、權限與叢集識別碼（`pg_control_system()` 的 `system_identifier`）只有檔案層級的還原才會保持；
  以 `pg_dump`／`pg_restore --no-owner` 方式還原會失去它們，`/api/summary` 的 `db_meta` 就會不同。

## API

| 方法與路徑 | 結果 |
| --- | --- |
| `GET /healthz` | 兩個資料庫都可連線、`www/` 可寫入且 SQLite 可讀時回 200 `{"ok":true,"database":true,"audit_database":true,"data_writable":true,"sqlite":true}`，否則 503（同結構） |
| `GET /api/summary` | 見下節，目錄項目的 `verify` 比對全部 9 個值 |
| `GET /api/items`、`POST /api/items` | 列出最新 1000 個項目；新增 `{"name":"…","body":"…"}`（只接受這兩個欄位；`name` 為英數字開頭、可含 `. _ -` 的 1–64 字元，`body` ≤ 64 KiB）→ 201 `{"id","name","sha256","path","archive"}` |
| `DELETE /api/items/<id>` | 刪除項目、檔案、硬連結與 SQLite 列，記錄稽核事件 → 200 |
| `GET /api/tree` | `{"root","count","digest","entries"}`：`/srv/data` 的完整清單（見「清單」） |
| `GET /api/sqlite` | `{"docs":[[item_id, name, path, sha256], …]}`（透過 SQLite 讀取，含 WAL） |
| `GET /api/db` | `{"items":[…],"events":[…],"meta":{…}}`（以 `dirs_app` 讀取） |

新增項目時應用依序：取得 `items` 的序號、寫入 `www/docs/<xx>/<yy>/<id>-<名稱>.txt`（0640，加上延伸屬性）、在
`www/archive/` 建立硬連結、寫入 SQLite、寫入 `dirs.items`（含以 `woowbk-dirs-app-key` 計算的 HMAC 簽章）、寫入
`dirs_audit.events`，最後把 `www/latest` 原子地改指到新檔案。錯誤回應為 `{"error":"<繁體中文說明>"}`。API 沒有身分驗證，
只發佈在設備的 127.0.0.1；它是測試夾具，不可對外開放。

### `/api/summary` 的定義

| 鍵 | 內容 | 證明什麼被正確還原 |
| --- | --- | --- |
| `items`、`events` | `dirs.items`、`dirs_audit.events` 的筆數（以 `dirs_app` 讀取） | 兩個資料庫與應用帳號的密碼 |
| `db_digest` | `{"items":[[id,name,sha256,signature]…],"events":[[id,item_id,action,name]…]}` 的標準 JSON SHA-256 | 資料庫內容 |
| `db_meta` | `{"user","system_identifier","server_major","roles","owners"}`：連線帳號、叢集識別碼、主版本、所有非 `pg_` 角色（名稱、可登入、超級使用者）、兩個資料庫與兩個資料表的擁有者 | 叢集層級的角色與擁有者（檔案層級還原） |
| `tree`、`tree_digest` | `/srv/data` 清單的項目數與 SHA-256 | 主機資料夾的類型、權限、容器內擁有者、大小、內容、修改時間、連結目標、延伸屬性、硬連結 |
| `sqlite` | `{"docs","digest"}`：SQLite `docs` 資料表（含 WAL 中的資料） | SQLite 主檔與 `-wal` 一起還原 |
| `title` | 設定檔的 `APP_TITLE` | 設定檔 |
| `signatures_valid` | 以**目前**的 `woowbk-dirs-app-key` 重新驗證每個項目的簽章 | 密鑰（差一個位元組，包括多一個結尾換行，就會是 `false`） |

標準 JSON：`sort_keys`、分隔符 `(',', ':')`、`ensure_ascii=False`、UTF-8。這些值只由持久資料決定，應用重新啟動不會改變
（`tools/check.py --stop-start` 實測），所以備份前後的兩次快照相同，還原後可以逐鍵比對。

### 清單（`app/treelist.py`）

同一份程式被應用（容器內 `/srv/data`）、`tools/check.py` 與 `tests/e2e/lab/dirs_e2e.py`（在擁有者的使用者命名空間內
`podman unshare python3 -I - <資料夾>`，看到的 ID 與容器相同，應用停止或被還原遮蔽時也能使用）使用，結果逐位元組可比。
不跟隨符號連結，依名稱（位元組）排序、深度優先，每個項目記錄：`path`、`type`（dir／file／symlink／fifo／other）、`mode`
（含 setuid／setgid／sticky）、`uid`、`gid`；一般檔案另有 `size`、`sha256`、`mtime`（整秒）；符號連結有 `target`；
檔案與資料夾的 `user.*` 延伸屬性以 `{名稱: 值的 SHA-256}` 記錄；同一 inode 的第二個以後的名稱有 `link`（第一個名稱）。
略過會變動的名稱：應用暫存檔（`.healthz-*`、`.tmp-*`）與 SQLite 的 `-wal`、`-shm`、`-journal`；`*.sqlite` 主檔只記錄
類型、權限與擁有者（內容以 SQL 比對）；不記錄資料夾的修改時間。

## 部署（以 appowner 身分，不經過備份引擎）

在實驗室執行 `tests/e2e/lab/deploy-dirs.sh a`，它依序：把本目錄複製到設備的 `/opt/woowbk-dirs`（root 擁有、所有人可讀）、
以 appowner 取得 `postgres:16-alpine`（已有則略過）、建置 `localhost/woowbk-dirs-app:1`、安裝 Quadlet 範本並
`daemon-reload`，最後執行 `tools/seed.py`。也可以在設備內手動執行：

```bash
# 設備內以 root 執行；woowbk-owner 以 runuser 和固定環境切換成 appowner，與引擎相同
woowbk-owner podman pull docker.io/library/postgres:16-alpine
woowbk-owner podman build --memory 512m -t localhost/woowbk-dirs-app:1 /opt/woowbk-dirs/app
woowbk-owner sh -c 'mkdir -p -m 0700 ~/.config && mkdir -p ~/.config/containers/systemd &&
  install -m 0644 /opt/woowbk-dirs/quadlet/* ~/.config/containers/systemd/'
woowbk-owner systemctl --user daemon-reload
woowbk-owner python3 /opt/woowbk-dirs/tools/seed.py --items 6
```

`seed.py` 每一步都可重複執行：建立缺少的三個隨機密鑰（已存在則保留；值只經由標準輸入傳給 podman，不出現在參數、環境
或輸出）、寫入設定檔（指定 `--title` 且與現值不同時重寫，並重新啟動執行中的應用）、建立缺少的主機資料夾項目（容器帳號
的擁有者以 `podman unshare` 設定）、啟動資料庫並等待 `pg_isready`、第一次時建立角色與第二個資料庫、啟動應用並等待
`/healthz`，再新增 `--items N` 個項目（含多位元組 UTF-8）、刪除最舊的 `--delete K` 個，`--owner-note T` 以擁有者身分
改寫 `README.txt`，最後輸出摘要。`--items 0 --no-start` 只輸出目前摘要；備份後用較小的數字、`--delete`、`--title` 或
`--owner-note` 就能「變更資料」。

## 驗證工具

```bash
woowbk-owner python3 /opt/woowbk-dirs/tools/check.py                # 唯讀：端點、digest、清單、擁有者對應、WAL、角色
woowbk-owner python3 /opt/woowbk-dirs/tools/check.py --write        # 另新增並刪除一個項目（新檔案屬於 UID 33，有硬連結）
woowbk-owner python3 /opt/woowbk-dirs/tools/check.py --db-outage    # 暫停資料庫：/healthz 變 503，恢復後 200
woowbk-owner python3 /opt/woowbk-dirs/tools/check.py --stop-start   # 停止服務：容器消失、主機資料夾與密鑰保留；重啟後摘要相同
```

唯讀檢查包含：擁有者在使用者命名空間內看到的清單（引擎讀取的方式）與容器內的清單逐位元組相同；主機上
`data/`、`www/`、PostgreSQL 資料目錄的擁有者等於依擁有者 `uid_map` 換算的 subuid；`app.sqlite-wal` 存在且不是空的。

離線單元測試（不需容器）：`python3 -B -m unittest discover -s tests/e2e -p 'test_*.py' -v`。

## 實驗室腳本與端到端情境

| 指令 | 作用 |
| --- | --- |
| `tests/e2e/lab/deploy-dirs.sh <a\|b> [--items N] [--delete K] [--title T] [--owner-note T] [--seed S] [--no-seed]` | 以 appowner 手動部署（見上） |
| `tests/e2e/lab/dirs-catalog.sh <a\|b> install\|remove\|status` | 以 root 安裝、移除或檢視受信任目錄項目與 Quadlet 範本，並顯示已安裝引擎對它的判斷 |
| `tests/e2e/lab/teardown-dirs.sh <a\|b> [--keep-image]` | 以擁有者身分移除整個部署（含主機資料夾與 `.woowbk-new-*`／`.woowbk-old-*`），讓設備成為全新還原目標 |
| `tests/e2e/lab/subids.sh <a\|b> [START:COUNT --reset-storage]` | 檢視或變更 appowner 的 subuid／subgid 範圍 |
| `python3 -I tests/e2e/lab/dirs_e2e.py <情境>` | 情境 `prep`、`d1`–`d6`，見 `tests/e2e/lab/README.md` |

## 已知限制

* 每個請求建立一個資料庫連線；只適合測試資料量。
* 應用第一次連到資料庫時以 `dirs_app` 自動建立資料表（`CREATE TABLE IF NOT EXISTS`）。
* PostgreSQL 主版本由映像標籤 `16-alpine` 決定；冷備份只能還原到相同主版本與 CPU 架構。
* 應用以 UID 33 執行，`data/` 根目錄與擁有者的檔案對它唯讀；應用只寫 `www/`。
