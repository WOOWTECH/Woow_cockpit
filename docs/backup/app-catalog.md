# 應用目錄項目：撰寫、測試與審查

對象：維護 Podman 應用套件的 WOOWTECH 工程師與審查者。一個應用要出現在「備份與還原」頁，設備上必須裝有它的**受信任目錄項目**（catalog entry）。本文說明目錄項目的格式、每個欄位的驗證規則、應用本身需要符合的條件，以及在實驗室設備測試與審查的方式。

規則依據 [CONTRACT.md](CONTRACT.md) 第 4、9 節，以及引擎的驗證程式 `backup-engine/woowbackup/catalog.py` 與轉接器 `backup-engine/woowbackup/adapters/quadlet_postgres.py`。兩者不一致時以程式為準，並回報規格維護者。主機資料夾（`data_dirs`）是 2026-11-13 開始的新功能，相關段落都註明了驗證狀態。管理者操作見 [../backup.md](../backup.md)；正式應用的盤點與接入順序見 [production-onboarding.md](production-onboarding.md)。

## 目錄項目的作用

- 一個應用一個 JSON 檔，明確列出擁有者帳號、Quadlet 檔、服務、PostgreSQL 資料庫、資料卷、主機資料夾、Podman secrets、設定檔、健康檢查與資料核對方式。引擎只備份與還原這裡列出的東西。
- **還原以本機目錄為準**：要寫入哪些密鑰名稱、設定檔路徑、資料卷、主機資料夾、資料庫、服務與範本，一律由目標設備上的目錄項目決定；備份檔只提供這些項目的內容。備份中有、本機目錄沒列的項目會被略過並在預檢提示；本機目錄要求、備份卻缺少的項目會讓該應用無法還原。
- 備份檔不能攜帶程式。備份與還原的步驟由引擎內建的轉接器（adapter）執行；這一版只有 `quadlet-postgres`。
- 全新部署（目標設備沒有這個應用）時，使用目錄項目指定的、root 擁有的部署範本；備份檔裡的 Quadlet 檔從不安裝。

## 檔案位置與權限

| 項目 | 位置 | 要求 |
| --- | --- | --- |
| 目錄項目 | `/etc/woowtech-cockpit/backup/apps/<id>.json` | 一般檔案、root 擁有、不可為符號連結、群組與其他人不可寫入（建議 0644）、最大 256 KiB；檔名必須是 `<id>.json` |
| 目錄資料夾 | `/etc/woowtech-cockpit/backup/` 與其下的 `apps/` | root 擁有、不可為符號連結、群組與其他人不可寫入。`manage.py install` 會建立為 0755 |
| 部署範本（選用） | `quadlet.template_dir`，必須位於 `/usr/local/share/woowtech-cockpit-backup/catalog/` 之內，建議 `catalog/<id>/quadlet/` | 範本資料夾與檔案 root 擁有、群組與其他人不可寫入、不可為符號連結；`quadlet.files` 列出的每個檔案都要存在，每個最大 1 MiB |

引擎載入 `apps/` 下所有 `.json` 檔。不符合規則的項目會被略過（不影響其他應用），原因顯示在頁面「總覽」上方的「備份設定提示」。擁有者帳號不存在於這台設備時，該項目同樣被略過。

### 目前的安裝方式

正式應用目錄項目的發佈機制（由各應用套件安裝）尚未建立。`manage.py` 只會安裝實驗室示範項目（`--backup-demo-catalog`）。在此之前，經審查的項目由設備管理者以 root 手動放置：

```bash
# <id> 為應用 ID；在目標設備上、從已審查的檔案執行
sudo install -d -o root -g root -m 0755 /usr/local/share/woowtech-cockpit-backup \
  /usr/local/share/woowtech-cockpit-backup/catalog \
  /usr/local/share/woowtech-cockpit-backup/catalog/<id> \
  /usr/local/share/woowtech-cockpit-backup/catalog/<id>/quadlet
sudo install -o root -g root -m 0644 quadlet/<每個 Quadlet 範本> /usr/local/share/woowtech-cockpit-backup/catalog/<id>/quadlet/
sudo install -o root -g root -m 0644 <id>.json /etc/woowtech-cockpit/backup/apps/<id>.json
```

放置後重新整理頁面：「總覽」應列出該應用，且沒有「備份設定提示」。`manage.py` 不追蹤這些手動放置的檔案：`verify` 不檢查它們，之後的 `install` 與 `rollback` 也不會修改或移除它們。

## 應用需要符合的條件（`quadlet-postgres`）

**部署方式**

- 由一個非 root 的 Linux 帳號以 rootless Podman 執行；該帳號已啟用 linger，使用者服務管理器在執行中。
- Quadlet 檔直接放在擁有者的 `~/.config/containers/systemd/`，是一般檔案（不可為符號連結，也不可放在子資料夾）；服務由 Quadlet 產生、以 `systemctl --user` 控制。
- `.container` 檔以 `Image=` 指定映像；不支援指向 `.image` 或 `.build` 的參照。映像名稱只能使用英數與 `._/:@-`。`localhost/` 映像無法從映像庫下載，還原到沒有這個映像的設備時，必須把映像包含在備份中。
- 健康檢查與資料核對端點由主機上的 root 以 HTTP 讀取，應用須把它們發佈到主機的 127.0.0.1（例如 `PublishPort=127.0.0.1:18090:8080`）。

**持久資料只能放在下列位置**

- 具名 Podman 資料卷。還原時以 `podman volume create <名稱>` 的預設選項重建，`.volume` 檔中設定的驅動或掛載選項不會重新套用。
  - 資料卷的內容必須能被 `podman volume import` 完整匯入：只能有一般檔案、目錄、FIFO、符號連結與硬連結；不可有裝置檔；符號連結的目標從連結所在目錄解析後不可離開資料卷（這是 podman 匯入的規則，例如放在資料卷最上層、目標為 `../x` 的連結會被拒絕）；檔案擁有者（UID／GID）必須在應用擁有者的 rootless 使用者命名空間對應範圍內；最多 2,000,000 個項目。備份時每個資料卷匯出都以這些規則檢查，不符合時備份失敗並指出資料卷與項目（應用已恢復執行）。
  - 還原時資料卷由引擎重新產生的 tar 匯入：非目錄檔案的 setuid／setgid 位元與 `user.*` 以外的延伸屬性（例如 file capabilities）不保留，結果頁「注意事項」會列出；修改時間只保留到秒。符號連結、硬連結、FIFO、長檔名、非 UTF-8 檔名、setgid／sticky 目錄、`user.*` 延伸屬性與不同擁有者都會保留（實驗室以 27 個項目實測）。依賴 setuid 程式或 file capabilities 的應用需另外評估。
- 主機資料夾：應用擁有者家目錄中、以 bind mount（`Volume=%h/<資料夾>:<容器內路徑>`）掛進容器的整個資料夾，見下方「主機資料夾（`data_dirs`）」。**新功能，實驗室端到端驗證尚未完成。**
- 應用自己的設定目錄 `~/.config/<id>/` 或 `~/.local/share/<id>/`（`<id>` 為應用 ID）之下的單一設定檔，每個最大 16 MiB。備份時照原樣讀取內容，不檢查檔案目前的權限；還原時一律以目錄宣告的 `mode`（最多 0644）寫入，例如原本 0664 的檔案還原後是 0644。還原時上層資料夾不存在會以擁有者身分建立（0700）。
- Podman secrets，每個 1–511,999 bytes（Podman 的限制），還原時以預設驅動重建。
- PostgreSQL 資料庫：列在 `postgres` 項目以 `pg_dump` 匯出（條件如下），或冷備份：資料檔隨資料卷或主機資料夾整份備份（見「PostgreSQL 冷備份」）。

**PostgreSQL（`postgres` 項目，以 `pg_dump` 匯出）**

資料庫有兩種接入方式：列在 `postgres`（本小節；備份時資料庫保持執行，只匯出目錄指定的單一資料庫），或不列 `postgres`、把資料庫的資料檔整份當成資料卷或主機資料夾備份（見下方「PostgreSQL 冷備份」；備份時資料庫一起停止，整個執行個體含角色都保留）。

- 資料庫在自己的容器內執行；`postgres[].container` 是容器名稱（Quadlet 的 `ContainerName=`）。資料放在專用的具名資料卷（`data_volume`），該資料卷不放其他資料，還原時會被刪除重建。
- 在容器內，目錄指定的 `user` 不需密碼即可透過本機 socket 執行 `psql`、`pg_dump`、`pg_restore` 與 `createdb`（引擎一律加上 `-w`，不提供密碼；實驗室使用的官方 `postgres:16-alpine` 映像預設如此），並有權讀取與重建整個資料庫。
- PostgreSQL 在容器內監聽 TCP 127.0.0.1:5432；就緒檢查使用 `pg_isready -h 127.0.0.1 -p 5432`。
- 資料卷是空的時，映像會自動初始化新的資料庫叢集（官方映像的行為）。初始化需要的密碼等設定應來自已列入目錄的 Podman secret 或設定檔，因為還原時會先重建它們，再啟動資料庫。
- 只備份目錄列出的單一資料庫，不含角色等叢集層級設定；匯入使用 `--no-owner --no-privileges`，所有物件改由目錄指定的 `user` 擁有。應用必須能接受這個結果（例如只使用這一個資料庫帳號）。
- 資料庫執行個體只應包含目錄宣告的資料庫（另有 `postgres`、`template0` 與 `template1`，依名稱排除；其他標為範本的資料庫也算）。原位還原會重建整個資料卷，執行個體中若有其他資料庫，預檢失敗、還原被拒絕；無法列出時也拒絕（只有在沒有還原前備份的還原中例外，見 [../backup.md](../backup.md) 的「無法建立還原前備份時」）。資料庫清單透過目錄宣告的資料庫讀取。其他角色，以及 `postgres` 資料庫中的資料表、函式或擴充功能（例如排程工作）不會保留，預檢會以「注意」列出。備份時作業紀錄也會註明這些資料庫、角色與物件不在備份中。
- 支援 PostgreSQL 10 以上。
- 資料庫服務不可相依（`Wants=`、`Requires=`）寫入服務，應由應用服務相依資料庫。還原時引擎先只啟動資料庫並匯入資料，之後才啟動其他服務；若應用提前啟動並建立資料表，單一交易的匯入會失敗並觸發自動回復。
- 備份的 PostgreSQL 主版本不可高於目標設備資料庫映像的主版本。建議以主版本固定映像標籤（例如 `postgres:16-alpine`）。

## 主機資料夾（`data_dirs`）

> **狀態（2026-11-13）：** 引擎、頁面與實驗室示範項目已完成，並在實驗室設備上實測原位還原、跨設備還原、自動回復、中斷後整理、惡意內容與全新部署衝突（D1–D6），以及掛載點與其他容器共用資料夾（D7）。安全審查（M1–M5、L1–L7）指出的問題已修正，修正後重新實測。本節依工程規格（[CONTRACT.md](CONTRACT.md)）撰寫。

很多應用把資料放在應用擁有者家目錄中的資料夾，再以 bind mount（Quadlet 的 `Volume=%h/<資料夾>:<容器內路徑>`）掛進容器，例如正式主機上的：

| 應用 | 主機資料夾（相對於擁有者家目錄） | 內容 |
| --- | --- | --- |
| Home Assistant | `homeassistant/config-preinstalled` | 整個設定資料夾，約 74 MB、3,344 個檔案，含 SQLite 資料庫與 WAL、`.storage`；容器在使用者命名空間內以 root 執行，檔案屬於擁有者本人與其 subuid |
| Nextcloud | `.local/share/nextcloud-office/html`、`…/data`、`…/postgres`、`…/redis` | `html` 約 897 MB、32,839 個檔案（含 `config/config.php`），`data` 約 80 MB，`postgres` 是 PostgreSQL 16 的資料目錄；檔案屬於容器內的 www-data、postgres 等帳號（主機上是 subuid） |
| Odoo | `.local/share/odoo18/addons` | 自訂模組，容器內唯讀 |

大小與檔案數是負責人 2026-11-13 在正式主機上量到的參考值，只用來說明規模；這些應用的目錄項目尚未建立。

### 宣告方式

```json
"data_dirs": [
  {"path": "homeassistant/config-preinstalled", "label": "設定資料夾"}
]
```

- `path`：相對於應用擁有者家目錄的資料夾路徑。與設定檔不同，**不限於** `.config/<id>/` 或 `.local/share/<id>/`，但下列規則全部適用：
  - 正規化的相對路徑（`/` 分隔），不可為空、不可以 `/` 開頭；每一段只能用 `A-Z a-z 0-9 . _ @ + -`，不可為空、`.` 或 `..`；
  - 不可是家目錄本身；不可等於、位於或包含 `.ssh`、`.gnupg`、`.config/systemd`、`.config/containers`、`.local/share/containers`、`.config/environment.d`、`.config/autostart`、`.config/dbus-1`、`.config/user-tmpfiles.d`、`.local/share/systemd`、`.local/share/dbus-1`、`.local/share/applications`、`.local/share/user-tmpfiles.d`、`.local/bin`、`.local/lib`、`bin`、`.bashrc.d`、`.config/fish`（登入金鑰、服務定義、使用者環境、登入時會執行的程式與殼層設定、Python 使用者套件、Podman 儲存區都不能由備份內容取代）；比對時不分大小寫；
  - 任何一段都不可包含 `.woowbk-`（保留給還原時的暫存資料夾名稱）；
  - 各項目不可互相重疊（一個不可位於另一個之內），也不可與 `config_files` 的任何路徑重疊；同一個擁有者的兩個應用，主機資料夾不可互相重疊，也不可包含另一個應用的設定檔（較晚載入的項目會被略過並在狀態中說明）。
- `label`：選填，頁面顯示用的中文說明。
- 最多 16 個；未定義的欄位一律拒絕（與其他欄位相同）。目錄格式版本仍是 `schema: 1`，沒有 `data_dirs` 的目錄項目與舊備份照常有效。
- 一個項目代表**整個資料夾**：沒有排除規則，資料夾裡的快取、記錄檔也會一起備份與還原。不需要的大型可重建資料請放到資料夾之外。

### 應用需要符合的條件

- **每個使用這個資料夾的服務都要列在 `writer_units`。** 備份時引擎只停止 `writer_units`。備份開始前，引擎會列出應用擁有者所有執行中的容器（不論是 Quadlet 的 `Volume=`／`Mount=`、Pod、`PodmanArgs` 或手動啟動的），只要有不會被停止的容器以可寫入方式掛載這個資料夾（或它的上層資料夾），備份就會在停止任何服務之前失敗並說明是哪個容器。唯讀掛載不影響備份，但還原時一樣會被擋下（見下方）。原則上不要讓其他應用共用資料夾。
- 資料夾**不可是掛載點，也不可包含掛載點**（另外掛載的檔案系統或 bind mount）。還原要在同一個掛載中替換整個資料夾：掛載點無法改名；資料夾內的掛載點會連同被取代的舊內容一起移走，成功後刪除時會刪到另一個掛載的內容。備份與還原前的檢查都會拒絕。資料放在另一顆磁碟時，請列出掛載點**之內**的資料夾，例如掛載點是 `~/data` 就列 `~/data/nextcloud`。
- 資料夾中設定了 POSIX ACL 權限的項目，備份不包含 ACL，備份紀錄會說明有幾個；擁有者不在應用擁有者 UID／GID 範圍內的檔案（例如 root 擁有），還原後會變成範圍內的 65534。
- 資料夾與其每一層上層資料夾都**不可是符號連結**；資料夾內的符號連結會原樣備份，但不會被跟隨到資料夾外。
- 容器以非 root 身分寫入時（例如 Nextcloud 的 www-data，UID 33），主機上檔案的擁有者是應用擁有者的 subuid。目標設備上應用擁有者的 subuid／subgid 範圍必須涵蓋備份中出現的最大 UID／GID，還原在任何變更之前會檢查。
- 還原會以新的資料夾**整個取代**舊的，不會合併：應用不能依賴在資料夾中保留還原前的檔案。

### 備份與還原時引擎做什麼

**備份**（在 `writer_units` 停止期間，與資料卷相同）：

1. 以應用擁有者身分、在他的 rootless 使用者命名空間內（`podman unshare`）讀取資料夾，所以 subuid 擁有的檔案也讀得到，並以容器內看到的擁有者記錄。保留權限、修改時間、符號連結、硬連結，以及可以保留的延伸屬性；不跟隨符號連結到資料夾外。資料夾本身或任何上層是符號連結時，備份失敗。
2. tar 經由引擎既有的擁有者管道串流到只有 root 可存取的暫存區，root 從不直接開啟擁有者家目錄中的路徑。
3. 在備份的內容清單中，每個應用多一個 `data_dirs` 清單（`path` 與 `entry`），每個資料夾是一個項目 `apps/<應用 ID>/dirs/<序號>.tar`。

**還原**：

1. 只寫入**本機目錄**列出的資料夾。每個資料夾 tar 都先以資料卷相同的規則完整檢查（不可有絕對路徑或 `..`、不可有位於符號連結之下的項目、只允許支援的檔案類型、擁有者必須在目標應用擁有者的 UID／GID 對應範圍內），再由引擎依檢查過的項目重新產生乾淨的 tar。
2. 以應用擁有者身分、在他的使用者命名空間內，把內容解到同一層的新資料夾 `<路徑>.woowbk-new-<作業 ID>`。
3. 對調：原位還原時把原資料夾改名為 `<路徑>.woowbk-old-<作業 ID>`，再把新資料夾改名為 `<路徑>`；每一步都拒絕跟隨符號連結。
4. 順序：服務停止後，先把**所有**資料夾都寫好新資料夾，這時還沒有改動任何既有資料；再還原應用機密、設定檔、資料卷與資料庫資料卷；對調前再列一次執行中的容器，若有任何容器掛載這些資料夾就停止還原（並自動回復）；最後依序對調。
5. 整個作業成功後才刪除 `.woowbk-old-…`：先改名為 `.woowbk-del-…` 再刪除，刪除時不會跨進其他掛載。
6. 還原失敗時自動回復：已對調的資料夾直接把 `.woowbk-old-<作業 ID>` 移回原位（不重新解壓，也不需要額外空間），失敗時寫入的內容先放到 `.woowbk-old-<作業 ID>-rollback`，回復確認無誤後刪除；失敗的還原沒有動到的資料夾保持原樣；只有找不到原內容的資料夾，才從還原前備份解出。
7. 全新部署：上層資料夾不存在時以應用擁有者身分建立；目標資料夾已存在且不是空的時，預檢失敗、不刪除任何東西。

**還原前的檢查**（頁面的預檢與還原作業的「相容性檢查」階段）另外確認：原位還原時資料夾存在、全新部署時不存在（或是空的）；資料夾不是掛載點、其中也沒有掛載點；不與 Podman 實際的儲存位置重疊；沒有其他服務或手動啟動的容器掛載它（唯讀也不行，對調後它會繼續用到被取代的舊內容）；磁碟空間（家目錄所在磁碟需要備份中這個應用資料量的兩倍；資料夾在另一顆磁碟時另外檢查那顆磁碟；回復時直接移回原內容，不需要第三份空間）；備份中最大的 UID／GID 能被目標應用擁有者的 subuid／subgid 對應；以及一般的映像檢查。

**中斷後的整理**：作業被強制終止或斷電時，系統在判定作業中斷時處理這個作業留下的 `.woowbk-new-…`、`.woowbk-old-…` 與 `.woowbk-del-…`（即使旁邊還有很多其他作業留下的資料夾也找得到）：完成刪除到一半的 `.woowbk-del-…`；`<路徑>` 不見時把舊資料夾移回，優先移回還原前的原內容，其次才是失敗時寫入的內容；移除沒寫完的新資料夾；其餘舊資料夾保留並說明各是什麼內容，絕不刪除僅存的一份。若作業是在還原已經成功、正在刪除舊內容時中斷，作業訊息會說明還原已完成、不需要再次還原。

## PostgreSQL 冷備份（資料檔整份備份）

PostgreSQL 的資料目錄放在具名資料卷或主機資料夾時，可以不用 `pg_dump`，改成在備份期間停止資料庫、整份備份資料檔：

1. **不要**列 `postgres` 項目（`"postgres": []` 或省略）。
2. 資料庫的資料卷列在 `volumes`，或資料目錄列在 `data_dirs`。
3. 資料庫服務列在 `units`（啟動順序第一個），**也**列在 `writer_units`，和所有應用服務一起停止。

```json
"units": ["woowbk-dirs-db.service", "woowbk-dirs-app.service"],
"writer_units": ["woowbk-dirs-db.service", "woowbk-dirs-app.service"],
"postgres": [],
"data_dirs": [
  {"path": ".local/share/woowbk-dirs/postgres", "label": "PostgreSQL 資料目錄"},
  {"path": "woowbk-dirs/data", "label": "應用資料（含 SQLite）"}
]
```

（實驗室主機資料夾示範項目 [catalog-examples/woowbk-dirs/catalog.json](../../catalog-examples/woowbk-dirs/catalog.json) 的寫法，由實驗室成員同時建置中。）

這樣備份時所有服務都停止（停止順序與 `units` 相反，應用先停、資料庫最後停；恢復時資料庫先啟動），資料檔是資料庫正常關閉後的一致狀態。和 `pg_dump` 方式比較：

| | `postgres` 項目（pg_dump） | 冷備份 |
| --- | --- | --- |
| 備份時資料庫 | 保持執行 | 一起停止，停機時間包含資料庫的停止與啟動 |
| 保留的內容 | 目錄指定的單一資料庫；角色與權限不保留，物件改由 `user` 擁有 | 整個執行個體：所有資料庫、角色、密碼、擁有者與權限都在資料檔中保留 |
| 執行個體中有其他資料庫 | 原位還原會被拒絕 | 一起備份與還原 |
| 備份時的檢查 | 以 `pg_restore` 完整讀取一次 | 引擎不知道這是資料庫，不檢查內容；只靠正常關閉 |
| 還原到的 PostgreSQL | 主版本不可低於備份時 | **主版本必須相同**（資料目錄格式不能跨主版本），CPU 架構也要相同 |

使用冷備份時：

- 資料庫映像以主版本固定標籤（例如 `postgres:16-alpine`），並讓容器有足夠時間正常關閉（例如 `PodmanArgs=--stop-timeout 60`）；被強制終止的資料庫只能靠 WAL 復原。
- 主版本不同時，還原後資料庫無法啟動，健康檢查不會通過，依一般流程應會自動回復；這個情況尚未實測。升級 PostgreSQL 主版本前後請各做一次備份。
- 引擎不會列出執行個體中的資料庫或角色，預檢也不檢查 PostgreSQL 版本；資料核對（`verify`）請涵蓋資料庫內容，健康檢查請確認資料庫可連線。
- 已驗證的範圍（2026-11-13）：**具名資料卷**的冷備份在實驗室 dev-a 以示範應用實測：備份暫停寫入約 4 秒，原位還原約 18 秒，資料核對（筆數、內容雜湊、設定檔與密鑰）與備份時一致；負責人另以同一方式在正式主機測試 Odoo（備份暫停 8 秒），還原後 205 個資料表的內容清單與 filestore 檔案清單和備份前相同。**主機資料夾**中的資料庫（Nextcloud 的形態）以實驗室示範項目 `woowbk-dirs`（PostgreSQL 16 資料目錄在主機資料夾，含額外角色與第二個資料庫）實測原位還原、跨設備還原（不同 UID 與 subuid 範圍）、自動回復與中斷後整理，角色、密碼與資料都與備份時一致。

## 範例

實驗室示範應用的項目（`catalog-examples/woowbk-demo/catalog.json`）：

```json
{
  "schema": 1,
  "id": "woowbk-demo",
  "name": "示範筆記應用",
  "description": "PostgreSQL、檔案與密鑰的備份還原示範應用",
  "owner": "appowner",
  "adapter": "quadlet-postgres",
  "quadlet": {
    "files": ["woowbk-demo.network", "woowbk-demo-db.container", "woowbk-demo-app.container"],
    "template_dir": "/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet"
  },
  "units": ["woowbk-demo-db.service", "woowbk-demo-app.service"],
  "writer_units": ["woowbk-demo-app.service"],
  "postgres": [
    {"id": "main", "container": "woowbk-demo-db", "unit": "woowbk-demo-db.service",
     "database": "notes", "user": "notes", "data_volume": "woowbk-demo-pgdata"}
  ],
  "volumes": [{"name": "woowbk-demo-files", "label": "上傳檔案"}],
  "secrets": [{"name": "woowbk-demo-db-password"}, {"name": "woowbk-demo-app-key"}],
  "config_files": [{"path": ".config/woowbk-demo/app.env", "mode": "0600"}],
  "health": [{"type": "http", "url": "http://127.0.0.1:18090/healthz", "expect_status": 200, "timeout_seconds": 90}],
  "verify": [
    {"id": "summary", "type": "http-json", "url": "http://127.0.0.1:18090/api/summary",
     "compare": ["notes", "files", "digest", "title", "signatures_valid"]}
  ]
}
```

資料庫服務排在 `units` 第一位且不列為寫入服務；應用服務是唯一的寫入服務。`/healthz` 在資料庫可連線且資料卷可寫入時才回 200；`/api/summary` 的五個值分別證明資料庫（`notes`）、資料卷（`files`）、兩者內容（`digest`）、設定檔（`title`）與密鑰（`signatures_valid`）都已正確還原。Quadlet 範本與應用細節見 [catalog-examples/woowbk-demo/README.md](../../catalog-examples/woowbk-demo/README.md)。

## 欄位與驗證規則（schema 1）

一般規則：

- 每一層都不接受未定義的欄位；JSON 必須是 UTF-8，不可有重複的鍵，不可使用 NaN 或 Infinity；整個檔案最大 256 KiB。
- 各清單內的名稱不可重複（服務、Quadlet 檔、資料庫 `id`／容器／資料卷、資料卷、主機資料夾路徑、密鑰、設定檔路徑、核對 `id`、`compare` 鍵）；主機資料夾之間、主機資料夾與設定檔之間也不可重疊。
- 文字欄位不可包含控制字元。

| 欄位 | 必填 | 規則 | 用途 |
| --- | --- | --- | --- |
| `schema` | 是 | 整數 `1` | 格式版本 |
| `id` | 是 | 2–41 個字元，見下方格式；檔名必須是 `<id>.json`，同一設備不可重複 | 應用識別；備份檔以此對應目錄 |
| `name` | 是 | 1–80 字 | 頁面顯示名稱 |
| `description` | 否 | 0–500 字 | 頁面說明 |
| `owner` | 是 | 見下方格式；不可為 `root`，對應的 UID 不可為 0；帳號必須存在於設備 | 應用擁有者 |
| `adapter` | 是 | 這一版只能是 `quadlet-postgres` | 轉接器 |
| `quadlet` | 是 | 物件，只能有 `files` 與 `template_dir` | Quadlet 設定 |
| `quadlet.files` | 是 | 1–32 個檔名，副檔名為 `.container`、`.network`、`.volume` 或 `.pod` | 擁有者 `~/.config/containers/systemd/` 中屬於此應用的 Quadlet 檔 |
| `quadlet.template_dir` | 否 | 正規化的絕對路徑，位於 `/usr/local/share/woowtech-cockpit-backup/catalog/` 之內 | 全新部署用的範本資料夾；沒有時無法還原到尚未部署此應用的設備 |
| `units` | 是 | 1–32 個 `.service` 名稱 | 啟動順序；停止時反向 |
| `writer_units` | 否 | 0–32 個，每個都必須在 `units` 中，且不可是任何 `postgres[].unit` | 備份時暫停的服務 |
| `postgres` | 否 | 0–8 個物件，每個都必須且只能有 `id`、`container`、`unit`、`database`、`user`、`data_volume` | 要匯出的資料庫 |
| `postgres[].unit` | — | 必須在 `units` 中，不可在 `writer_units` 中 | 資料庫服務 |
| `postgres[].data_volume` | — | 不可同時列在 `volumes` | 資料庫的資料卷，還原時刪除重建 |
| `volumes` | 否 | 0–32 個物件：`name` 必填，`label` 選填（0–80 字） | 要備份的資料卷 |
| `data_dirs` | 否 | 0–16 個物件：`path` 必填，`label` 選填；路徑規則見「主機資料夾（`data_dirs`）」 | 要備份的主機資料夾 |
| `secrets` | 否 | 0–64 個物件，只有 `name` | 要備份的 Podman secrets |
| `config_files` | 否 | 0–64 個物件，`path` 與 `mode` 都必填 | 要備份的設定檔 |
| `health` | 否 | 0–8 個物件：`type`、`url` 必填，`type` 只能是 `http`；`expect_status` 100–599（預設 200）；`timeout_seconds` 1–600（預設 60） | 健康檢查 |
| `verify` | 否 | 0–8 個物件，`id`、`type`、`url`、`compare` 都必填；`type` 只能是 `http-json`；`compare` 1–32 個鍵 | 資料核對 |

名稱格式（正規表示式）：

```text
id                                    ^[a-z0-9][a-z0-9-]{1,40}$
owner                                 ^[a-z_][a-z0-9_-]{0,31}$
units[]、writer_units[]、postgres[].unit
                                      ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}\.service$
quadlet.files[]                       ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,190}\.(container|network|volume|pod)$
postgres[].container、postgres[].data_volume、volumes[].name
                                      ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$
secrets[].name                        ^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}$
postgres[].id、verify[].id            ^[a-z0-9][a-z0-9_-]{0,31}$
postgres[].database、postgres[].user   ^[A-Za-z_][A-Za-z0-9_]{0,62}$
verify[].compare[]                    ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$
config_files[].path 的每一段          ^[A-Za-z0-9._@+-]{1,255}$，且整個路徑以 .config/<id>/ 或 .local/share/<id>/ 開頭
data_dirs[].path 的每一段             只能用 A-Z a-z 0-9 . _ @ + -，不可為空、. 或 ..（長度上限依 CONTRACT）
config_files[].mode                   ^0[0-7]{3}$，且不可超過 0644
quadlet.template_dir 的每一段          ^[A-Za-z0-9._@+-]{1,255}$，不可為 . 或 ..
```

`config_files[].path`：相對於擁有者家目錄，必須位於應用自己的設定目錄 `.config/<id>/` 或 `.local/share/<id>/` 之下，最多 1024 字元；每一段 1–255 字元，只能用 `A-Z a-z 0-9 . _ @ + -`，不可為空、`.` 或 `..`。即使應用 ID 與下列目錄同名，也不可指向 `.config/systemd/`、`.config/containers/`、`.config/environment.d/`、`.config/autostart/`、`.config/dbus-1/`、`.config/user-tmpfiles.d/`、`.local/share/systemd/`、`.local/share/containers/`、`.local/share/dbus-1/`、`.local/share/applications/`：服務定義、使用者環境與 Podman 設定只能來自受信任的範本。`mode` 不可有執行權限，群組與其他人不可寫入；放密碼的檔案請用 `0600`。

`health[].url`、`verify[].url`：只能是 `http://127.0.0.1:<埠>/…` 或 `http://localhost:<埠>/…`，埠 1–65535，最多 500 字元，路徑只能用 URL 安全字元。引擎不跟隨轉址、不使用 proxy，回應本文最多讀取 1 MiB。

### 修改目錄項目的相容性

備份會記錄當時目錄項目的 SHA-256。還原時目錄已不同只會提示「此設備的應用設定與備份時不同；將以此設備的設定為準」，但依授權規則：

- **新增或改名**資料庫、資料卷、主機資料夾、密鑰或設定檔路徑後，舊備份缺少這些項目，會在新目錄下**無法還原**。例如替既有應用加上 `data_dirs` 後，加上之前建立的備份就不能再還原這個應用。
- 把資料庫從 `postgres` 項目改成冷備份（或反過來）也是這種變更：舊備份缺少新目錄要求的項目（資料卷、主機資料夾或資料庫匯出）。
- **移除**項目後，舊備份中的該項目會被略過。

規劃應用升版時要把這點納入：需要還原舊備份的設備，必須保留舊的項目名稱，或在升版前重新備份。

## 服務順序與 `writer_units`

- `units` 是啟動順序，停止時反向。還原時引擎先啟動資料庫服務並匯入資料，再依 `units` 順序啟動其餘服務。只需列出 `.container` 產生的服務；`.network`、`.volume`、`.pod` 產生的輔助服務由引擎依 `quadlet.files` 自行處理。
- 備份時只暫停 `writer_units` 中正在執行的服務；`postgres` 項目的資料庫保持執行以便 `pg_dump`。**所有會寫入資料庫、資料卷、主機資料夾或設定檔的服務都要列入**：主服務、worker、排程、webhook 處理、會把資料存到已列入資料卷或主機資料夾的快取或佇列等。沒列入的服務在備份期間繼續寫入，資料庫匯出、資料卷與主機資料夾就可能來自不同時間點。
- 主機資料夾與冷備份的資料卷：**每個掛載它的服務**都要列入，包括資料庫服務本身（見「PostgreSQL 冷備份」）。
- 資料卷或主機資料夾若被其他應用的服務共用，這個項目無法暫停那些服務，備份會不一致；共用需在審查時特別評估（見 [production-onboarding.md](production-onboarding.md)）。
- 每個服務停止的逾時為 180 秒、啟動為 600 秒。暫停期間（停止到重新啟動完成）就是應用停機時間，會量測並記錄在備份中；寫入服務應能快速停止與啟動。
- 匯出後一定會重新啟動被暫停的服務（每個最多試兩次）；仍無法啟動時備份失敗，訊息指出是哪個服務。備份開始時沒有執行的服務不會被啟動或停止。

## 健康檢查（`health`）

- **何時使用**：還原後（未通過即視為還原失敗並自動回復），以及備份後（只在備份前應用完整執行時檢查，未通過只記錄警告）。
- **方式**：每 2 秒對 `url` 送一次 GET，直到回應狀態碼等於 `expect_status` 或超過 `timeout_seconds`。單次請求最多等 10 秒。多個檢查都必須通過。
- **設計建議**：只在應用真的能服務時回應預期狀態，例如同時確認資料庫可連線、資料卷可寫入（示範應用的 `/healthz`）。不可有副作用，不可需要登入。`timeout_seconds` 要涵蓋還原後的冷啟動（載入映像、資料庫初始化、應用啟動），示範應用使用 90 秒。
- 沒有設定 `health` 時，還原只依服務能否啟動與資料核對判斷，建議至少設定一個。

## 資料核對（`verify`）

- **流程**：備份時，在暫停寫入服務**之前**讀取 `url`，必須回 HTTP 200 與 JSON 物件；保存 `compare` 列出的鍵的值（每個核對項目的值轉成 JSON 後最多 16,384 個字元）。服務恢復後會再讀一次（備份前應用只部分執行時，讀不到會重試到目錄設定的健康檢查逾時）：兩次相同才保存快照，不同或讀不到就不保存（作業紀錄會說明）。還原並通過健康檢查後，再讀一次並逐鍵比對，任何一個值不同就視為還原失敗並自動回復。結果頁以「備份時／還原後」表格列出每個值。
- **讀不到或沒有保存快照時**：備份仍會完成並記錄警告，但用這份備份還原時會略過比對，結果顯示「未比對」。
- **設計建議**：
  - 值必須只由持久資料決定、可重現：筆數、內容雜湊、來自設定檔的值、用密鑰計算的檢查結果。示範應用的 `/api/summary` 同時涵蓋資料庫、資料卷、設定檔與密鑰（`signatures_valid` 用目前的密鑰重新驗證每筆資料的 HMAC，密鑰差一個位元組就會變成 `false`）。
  - 不要放時間戳記、執行時間、請求計數、隨機值、快取統計，或應用每次啟動都會改變的值。
  - 端點須唯讀、只發佈在 127.0.0.1、15 秒內回應、不需登入。引擎不送任何帳密；HTTP 介面必須登入的應用目前無法使用 `verify`，請先不設定（還原結果會顯示「未比對」）。以 SQL 核對的擴充見 [production-onboarding.md](production-onboarding.md)。
- **時間差注意**：快照在暫停寫入服務之前讀取（端點通常由寫入服務本身提供），與實際匯出的資料之間有短暫空檔。若應用在這段時間（包括服務停止的過程中）仍會改變被比對的值，恢復後的第二次讀取就會不同，這份備份便沒有快照、還原時無法比對資料。只比對在這段空檔內不會變動的值，並確保所有寫入都來自 `writer_units`。
- **未套用的設定變更**：設定檔已修改但服務尚未重新啟動時，備份重新啟動服務會讓新設定生效；比對來自設定檔的值（例如示範的 `title`）因此改變時，同樣不會保存快照。這是管理者操作面的已知限制，見 [../backup.md](../backup.md)。

## 部署範本（`quadlet.template_dir`）

- 只在**全新部署**時使用（目標設備沒有此應用的任何 Quadlet 檔）：引擎以擁有者身分把範本寫入 `~/.config/containers/systemd/`（0644），執行 `systemctl --user daemon-reload`，再重建密鑰、設定檔、資料卷與資料庫。原位還原不使用範本，設備上現有的 Quadlet 檔保持不變。
- 全新部署前，目錄列出的資料卷、資料庫資料卷、範本 `.volume` 檔建立的資料卷、密鑰與設定檔都不可已存在，否則預檢失敗；因為全新部署失敗時會移除它建立的所有東西，既有的同名項目會一起被刪除。主機資料夾不可已存在且有內容（空資料夾可以），上層資料夾不存在時以擁有者身分建立。
- 還原期間（原位與全新部署），資料庫以外的服務會被暫時停用（`systemctl --user mask`），資料匯入完成後才恢復並啟動；還原中斷時它們保持停用，「總覽」會顯示提示。應用的設計不應依賴在還原過程中自行啟動或被其他服務帶起。
- 範本必須與正式部署一致：容器名稱、資料卷名稱、密鑰名稱、設定檔路徑都要與目錄項目相同。
- 範本對所有帳號可讀，**不可包含任何密鑰或密碼**；機密請用 Podman secrets（`Secret=`），或列入目錄、權限 0600 的設定檔。
- 範本應與主機無關：不要綁定特定主機 IP 或網域，主機相關的值放在設定檔，並在跨設備還原後由管理者確認。
- 建議加上 `[Install] WantedBy=default.target`，配合 linger 在開機時自動啟動（示範應用的做法）。

## 離線檢查格式

在 repository 根目錄，用引擎的驗證程式檢查一份目錄項目（不需要 root，不連到任何設備）：

```bash
python3 -I -B -c '
import sys, types
sys.path.insert(0, "backup-engine")
from woowbackup.catalog import parse_json_bytes, validate_entry
from woowbackup.errors import BackupError
from woowbackup.paths import Paths
try:
    data = parse_json_bytes(open(sys.argv[1], "rb").read())
    app = validate_entry(data, paths=Paths(), user_lookup=lambda name: types.SimpleNamespace(pw_uid=1001))
except (ValueError, UnicodeDecodeError) as error:
    sys.exit(f"不是有效的 JSON：{error}")
except BackupError as error:
    sys.exit(f"{error.code}：{error.message}")
print("通過：", app.id, "服務", ", ".join(app.units))
' path/to/<id>.json
```

這只檢查欄位與格式，並假設擁有者帳號存在；不檢查檔案擁有者與權限、範本檔是否存在，也不檢查應用實際的部署。`scripts/check_source.py` 以同一個驗證程式檢查示範項目。

## 在實驗室設備測試

規則：只在兩台實驗室設備測試，所有容器操作只經 `~/.woowbk-lab/bin/labpodman` 與 `tests/e2e/lab/` 的腳本，**不可以正式應用或其資料測試；正式主機只能在負責人同意下使用示範應用**；只用合成的測試資料，不可帶入正式密鑰。實驗室是共用的，安裝額外項目前先與其他測試者協調，測完移除。設備與腳本說明見 [tests/e2e/lab/README.md](../../tests/e2e/lab/README.md)。

1. **啟動並安裝來源**：`tests/e2e/lab/up.sh a`、`up.sh b`（啟動前會確認主機可用記憶體至少 1200 MB），再以 `tests/e2e/lab/deploy-src.sh a`、`b` 安裝目前工作樹。
2. **在 dev-a 部署應用**：以 `tests/e2e/lab/owner.sh a …`（以 appowner 執行，方式與引擎相同）取得或建置映像、由標準輸入建立 secrets、寫入設定檔與 Quadlet 檔、`systemctl --user daemon-reload` 後啟動，並寫入可核對的測試資料。可參考 `tests/e2e/lab/deploy-demo.sh`。設備記憶體上限為 768 MiB，巢狀容器請設定記憶體上限（例如 Quadlet 的 `PodmanArgs=--memory 256m`）。
3. **放入目錄項目與範本**：兩台設備都要放。`tests/e2e/lab/exec.sh` 以 root 在設備內執行指令，並把標準輸入傳給它，例如 `tests/e2e/lab/exec.sh a sh -c 'cat > /root/<id>.json' < <id>.json`，再於設備內依「目前的安裝方式」的 `install` 指令放到正確位置。實驗室的擁有者帳號是 `appowner`（dev-a 為 UID 1001、dev-b 為 1007）。
4. **確認載入**：`tests/e2e/lab/engine.sh a status` 的 `apps` 列出此應用、`state` 為 `running`、`problems` 是空的，且 `warnings` 沒有它的訊息。
5. **跑完整情境**（引擎呼叫格式見 `engine.sh` 檔頭；帶金鑰的請求以 `-` 從標準輸入提供）：
   - 同機：建立金鑰 → 含映像與不含映像各備份一次 → 變更資料 → 原位還原 → 健康檢查通過、`verification` 全部一致、還原前備份列出。
   - 跨設備：從 dev-a 下載、上傳到 dev-b（應用未部署、UID 不同）→ 緊急金鑰 → 預檢為全新部署 → 還原 → 資料相同，應用可寫入新資料。
   - 失敗回復：讓還原在開始變更後失敗（例如讓健康檢查不通過）→ 「已自動回復」，資料等於還原前。
   - 缺映像：不含映像的備份還原到沒有該映像的設備 → 預檢失敗，沒有任何變更。
   - 中斷：在「還原資料」階段終止還原作業 → 「已中斷」→ 用還原前備份還原。
   - 洩漏：作業紀錄、日誌、索引與 journal 不含此應用的密鑰內容。
   - 記錄備份時間、寫入暫停秒數（作業結果的 `downtime_seconds`）、還原停機時間，以及映像、PostgreSQL 與應用版本。
6. **保存證據**：寫到 `~/.woowbk-lab/evidence/`，不可包含任何密鑰或金鑰。
7. **清理**：移除測試應用與目錄項目，或以 `tests/e2e/lab/reset.sh b --up` 重設 dev-b（會刪除該設備所有資料卷與備份）。

現有的 `tests/e2e/lab/cli_e2e.py`、`ui_e2e.mjs` 與 `hardening.py` 是為 `woowbk-demo` 撰寫的，新應用需要調整或另寫測試驅動程式，也可依上列步驟以 `engine.sh` 與頁面手動執行。

使用主機資料夾的應用另外要測：

- 檔案保真度：在容器內列出資料夾的類型、擁有者（含非 root 的容器帳號）、權限、大小、修改時間、連結目標與內容雜湊，原位還原與跨設備（不同 UID、不同 subuid 範圍：dev-a 與 dev-b 的範圍不同，以 `/etc/subuid` 確認）還原後逐項比對。
- 冷備份的資料庫：還原後角色、密碼、擁有者與權限可用（應用以原本的資料庫帳號登入）。
- 中斷：在「還原資料」階段終止作業，確認 `<路徑>`、`.woowbk-new-…`、`.woowbk-old-…` 被整理成安全的狀態並在作業訊息中說明。
- 全新部署時目標資料夾已存在且有內容：預檢失敗，沒有刪除任何東西。
- 掛載點與共用：資料夾之下有掛載、資料夾本身是掛載點（含同一檔案系統的 bind mount）、其他容器以唯讀或可寫入方式掛載它時，備份與還原前的檢查會擋下並說明原因，且沒有停止任何服務。

實驗室的主機資料夾示範項目在 `catalog-examples/woowbk-dirs/`（PostgreSQL 資料目錄與應用資料都在主機資料夾、以非 root 的容器帳號寫入，冷備份），部署腳本為 `tests/e2e/lab/deploy-dirs.sh` 與 `dirs-catalog.sh`，情境驅動程式為 `tests/e2e/lab/dirs_e2e.py`（D1–D7）。

## 審查清單

送審時附上目錄項目、部署範本、實驗室證據與測試紀錄。審查者逐項確認：

- [ ] **範圍完整**：應用所有持久狀態（資料庫、資料卷、主機資料夾、密鑰、設定檔）都已列入；Quadlet 檔中每個 `Volume=%h/…` 掛載都已列在 `data_dirs`，或有不需要備份的理由；沒有列入不必要的敏感檔案。
- [ ] **擁有者**：一般帳號、非 root，與實際部署帳號一致。
- [ ] **服務**：`units` 順序正確；`writer_units` 涵蓋所有寫入者與每個掛載主機資料夾的服務；`postgres` 項目的資料庫服務不在其中、也不相依寫入服務（冷備份則相反：資料庫服務必須在其中）；共用資料卷或主機資料夾已評估。
- [ ] **PostgreSQL**：`postgres` 項目方式：`container`、`unit`、`database`、`user`、`data_volume` 正確；容器內本機 socket 免密碼可用；執行個體沒有未宣告的資料庫；應用能接受物件由 `user` 擁有、角色不保留；版本 10 以上，映像以主版本固定。冷備份方式：沒有 `postgres` 項目，資料卷或資料目錄已列入，資料庫服務在 `writer_units`，映像以主版本固定，停止逾時足以正常關閉。
- [ ] **主機資料夾**：路徑與 Quadlet 掛載一致、符合路徑規則、沒有符號連結、不是掛載點也不包含掛載點、沒有其他應用或手動啟動的容器掛載它；整個資料夾都需要備份（沒有排除規則）；目標設備應用擁有者的 subuid／subgid 範圍涵蓋資料夾中的擁有者；應用能接受還原時整個資料夾被取代；實驗室已驗證檔案保真度與中斷後的整理。
- [ ] **資料卷內容**：符合匯入規則（沒有裝置檔、沒有目標會離開資料卷的符號連結、擁有者在 UID／GID 對應範圍內、項目數在上限內）；應用不依賴 setuid／setgid 檔案或 file capabilities，或已評估還原後失去它們的影響。
- [ ] **映像**：`Image=` 可取得；`localhost/` 映像已在文件中註明跨設備需包含映像。
- [ ] **設定檔與密鑰**：路徑與名稱和應用實際使用的一致；設定檔位於 `.config/<id>/` 或 `.local/share/<id>/`；權限不超過 0644，放密碼的檔案為 0600；密鑰大小在限制內。
- [ ] **部署範本**：與正式部署一致、與主機無關、不含密鑰；全新部署後應用可正常啟動。
- [ ] **健康檢查**：反映應用真正可用；逾時足以涵蓋冷啟動；無副作用。
- [ ] **資料核對**：值穩定可重現，涵蓋資料庫、資料卷、設定檔與密鑰；唯讀、不需登入；已評估快照時間差。
- [ ] **相容性**：與先前版本的目錄項目相比，沒有讓需要還原的舊備份失去必要項目。
- [ ] **檔案與權限**：離線檢查通過；放到設備後，頁面沒有「備份設定提示」（`status` 的 `warnings` 是空的）。
- [ ] **實驗室證據**：同機、跨設備（不同 UID）、失敗回復、缺映像、中斷與洩漏檢查都通過；已記錄停機時間與版本。
- [ ] **正式主機**：第一次正式備份會暫停寫入服務，已排定維護時段並取得同意（見 [production-onboarding.md](production-onboarding.md)）。
