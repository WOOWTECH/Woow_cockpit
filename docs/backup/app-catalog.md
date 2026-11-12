# 應用目錄項目：撰寫、測試與審查

對象：維護 Podman 應用套件的 WOOWTECH 工程師與審查者。一個應用要出現在「備份與還原」頁，設備上必須裝有它的**受信任目錄項目**（catalog entry）。本文說明目錄項目的格式、每個欄位的驗證規則、應用本身需要符合的條件，以及在實驗室設備測試與審查的方式。

規則依據 [CONTRACT.md](CONTRACT.md) 第 4、9 節，以及引擎的驗證程式 `backup-engine/woowbackup/catalog.py` 與轉接器 `backup-engine/woowbackup/adapters/quadlet_postgres.py`。兩者不一致時以程式為準，並回報規格維護者。管理者操作見 [../backup.md](../backup.md)；正式應用的盤點與接入順序見 [production-onboarding.md](production-onboarding.md)。

## 目錄項目的作用

- 一個應用一個 JSON 檔，明確列出擁有者帳號、Quadlet 檔、服務、PostgreSQL 資料庫、資料卷、Podman secrets、設定檔、健康檢查與資料核對方式。引擎只備份與還原這裡列出的東西。
- **還原以本機目錄為準**：要寫入哪些密鑰名稱、設定檔路徑、資料卷、資料庫、服務與範本，一律由目標設備上的目錄項目決定；備份檔只提供這些項目的內容。備份中有、本機目錄沒列的項目會被略過並在預檢提示；本機目錄要求、備份卻缺少的項目會讓該應用無法還原。
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
- `.container` 檔以 `Image=` 指定映像；不支援指向 `.image` 或 `.build` 的參照。映像名稱只能使用英數與 `._/:@-`。`localhost/` 映像無法從映像庫下載，跨設備還原時必須把映像包含在備份中。
- 健康檢查與資料核對端點由主機上的 root 以 HTTP 讀取，應用須把它們發佈到主機的 127.0.0.1（例如 `PublishPort=127.0.0.1:18090:8080`）。

**持久資料只能放在下列位置**

- 具名 Podman 資料卷。不支援主機資料夾掛載（bind mount）。還原時以 `podman volume create <名稱>` 的預設選項重建，`.volume` 檔中設定的驅動或掛載選項不會重新套用。
- 應用自己的設定目錄 `~/.config/<id>/` 或 `~/.local/share/<id>/`（`<id>` 為應用 ID）之下的單一設定檔，每個最大 16 MiB。還原時上層資料夾不存在會以擁有者身分建立（0700）。
- Podman secrets，每個 1–511,999 bytes（Podman 的限制），還原時以預設驅動重建。
- PostgreSQL 資料庫，條件如下。

**PostgreSQL**

- 資料庫在自己的容器內執行；`postgres[].container` 是容器名稱（Quadlet 的 `ContainerName=`）。資料放在專用的具名資料卷（`data_volume`），該資料卷不放其他資料，還原時會被刪除重建。
- 在容器內，目錄指定的 `user` 不需密碼即可透過本機 socket 執行 `psql`、`pg_dump`、`pg_restore` 與 `createdb`（引擎一律加上 `-w`，不提供密碼；實驗室使用的官方 `postgres:16-alpine` 映像預設如此），並有權讀取與重建整個資料庫。
- PostgreSQL 在容器內監聽 TCP 127.0.0.1:5432；就緒檢查使用 `pg_isready -h 127.0.0.1 -p 5432`。
- 資料卷是空的時，映像會自動初始化新的資料庫叢集（官方映像的行為）。初始化需要的密碼等設定應來自已列入目錄的 Podman secret 或設定檔，因為還原時會先重建它們，再啟動資料庫。
- 只備份目錄列出的單一資料庫，不含角色等叢集層級設定；匯入使用 `--no-owner --no-privileges`，所有物件改由目錄指定的 `user` 擁有。應用必須能接受這個結果（例如只使用這一個資料庫帳號）。
- 資料庫執行個體只應包含目錄宣告的資料庫（另有 `postgres` 與範本資料庫）。原位還原會重建整個資料卷，執行個體中若有其他資料庫，預檢失敗、還原被拒絕；其他角色不會保留，預檢會以警告列出。備份時作業紀錄也會註明這些資料庫與角色不在備份中。
- 支援 PostgreSQL 10 以上。
- 資料庫服務不可相依（`Wants=`、`Requires=`）寫入服務，應由應用服務相依資料庫。還原時引擎先只啟動資料庫並匯入資料，之後才啟動其他服務；若應用提前啟動並建立資料表，單一交易的匯入會失敗並觸發自動回復。
- 備份的 PostgreSQL 主版本不可高於目標設備資料庫映像的主版本。建議以主版本固定映像標籤（例如 `postgres:16-alpine`）。

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
- 各清單內的名稱不可重複（服務、Quadlet 檔、資料庫 `id`／容器／資料卷、資料卷、密鑰、設定檔路徑、核對 `id`、`compare` 鍵）。
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
config_files[].mode                   ^0[0-7]{3}$，且不可超過 0644
quadlet.template_dir 的每一段          ^[A-Za-z0-9._@+-]{1,255}$，不可為 . 或 ..
```

`config_files[].path`：相對於擁有者家目錄，必須位於應用自己的設定目錄 `.config/<id>/` 或 `.local/share/<id>/` 之下，最多 1024 字元；每一段 1–255 字元，只能用 `A-Z a-z 0-9 . _ @ + -`，不可為空、`.` 或 `..`。即使應用 ID 與下列目錄同名，也不可指向 `.config/systemd/`、`.config/containers/`、`.config/environment.d/`、`.config/autostart/`、`.config/dbus-1/`、`.config/user-tmpfiles.d/`、`.local/share/systemd/`、`.local/share/containers/`、`.local/share/dbus-1/`、`.local/share/applications/`：服務定義、使用者環境與 Podman 設定只能來自受信任的範本。`mode` 不可有執行權限，群組與其他人不可寫入；放密碼的檔案請用 `0600`。

`health[].url`、`verify[].url`：只能是 `http://127.0.0.1:<埠>/…` 或 `http://localhost:<埠>/…`，埠 1–65535，最多 500 字元，路徑只能用 URL 安全字元。引擎不跟隨轉址、不使用 proxy，回應本文最多讀取 1 MiB。

### 修改目錄項目的相容性

備份會記錄當時目錄項目的 SHA-256。還原時目錄已不同只會提示「此設備的應用設定與備份時不同；將以此設備的設定為準」，但依授權規則：

- **新增或改名**資料庫、資料卷、密鑰或設定檔路徑後，舊備份缺少這些項目，會在新目錄下**無法還原**。
- **移除**項目後，舊備份中的該項目會被略過。

規劃應用升版時要把這點納入：需要還原舊備份的設備，必須保留舊的項目名稱，或在升版前重新備份。

## 服務順序與 `writer_units`

- `units` 是啟動順序，停止時反向。還原時引擎先啟動資料庫服務並匯入資料，再依 `units` 順序啟動其餘服務。只需列出 `.container` 產生的服務；`.network`、`.volume`、`.pod` 產生的輔助服務由引擎依 `quadlet.files` 自行處理。
- 備份時只暫停 `writer_units` 中正在執行的服務；資料庫保持執行以便 `pg_dump`。**所有會寫入資料庫、資料卷或設定檔的服務都要列入**：主服務、worker、排程、webhook 處理、會把資料存到已列入資料卷的快取或佇列等。沒列入的服務在備份期間繼續寫入，資料庫匯出與資料卷匯出就可能來自不同時間點。
- 資料卷若被其他應用的服務共用，這個項目無法暫停那些服務，備份會不一致；共用資料卷需在審查時特別評估（見 [production-onboarding.md](production-onboarding.md)）。
- 每個服務停止的逾時為 180 秒、啟動為 600 秒。暫停期間（停止到重新啟動完成）就是應用停機時間，會量測並記錄在備份中；寫入服務應能快速停止與啟動。
- 匯出後一定會重新啟動被暫停的服務（每個最多試兩次）；仍無法啟動時備份失敗，訊息指出是哪個服務。備份開始時沒有執行的服務不會被啟動或停止。

## 健康檢查（`health`）

- **何時使用**：還原後（未通過即視為還原失敗並自動回復），以及備份後（只在備份前應用完整執行時檢查，未通過只記錄警告）。
- **方式**：每 2 秒對 `url` 送一次 GET，直到回應狀態碼等於 `expect_status` 或超過 `timeout_seconds`。單次請求最多等 10 秒。多個檢查都必須通過。
- **設計建議**：只在應用真的能服務時回應預期狀態，例如同時確認資料庫可連線、資料卷可寫入（示範應用的 `/healthz`）。不可有副作用，不可需要登入。`timeout_seconds` 要涵蓋還原後的冷啟動（載入映像、資料庫初始化、應用啟動），示範應用使用 90 秒。
- 沒有設定 `health` 時，還原只依服務能否啟動與資料核對判斷，建議至少設定一個。

## 資料核對（`verify`）

- **流程**：備份時，在暫停寫入服務**之前**讀取 `url`，必須回 HTTP 200 與 JSON 物件；保存 `compare` 列出的鍵的值（每個核對項目的值轉成 JSON 後最多 16,384 個字元）。若備份前應用完整執行，服務恢復後會再讀一次：兩次相同才保存快照，不同就不保存（作業紀錄會說明）。還原並通過健康檢查後，再讀一次並逐鍵比對，任何一個值不同就視為還原失敗並自動回復。結果頁以「備份時／還原後」表格列出每個值。
- **讀不到或沒有保存快照時**：備份仍會完成並記錄警告，但用這份備份還原時會略過比對，結果顯示「未比對」。
- **設計建議**：
  - 值必須只由持久資料決定、可重現：筆數、內容雜湊、來自設定檔的值、用密鑰計算的檢查結果。示範應用的 `/api/summary` 同時涵蓋資料庫、資料卷、設定檔與密鑰（`signatures_valid` 用目前的密鑰重新驗證每筆資料的 HMAC，密鑰差一個位元組就會變成 `false`）。
  - 不要放時間戳記、執行時間、請求計數、隨機值、快取統計，或應用每次啟動都會改變的值。
  - 端點須唯讀、只發佈在 127.0.0.1、15 秒內回應、不需登入。引擎不送任何帳密；HTTP 介面必須登入的應用目前無法使用 `verify`，請先不設定（還原結果會顯示「未比對」）。以 SQL 核對的擴充見 [production-onboarding.md](production-onboarding.md)。
- **時間差注意**：快照在暫停寫入服務之前讀取（端點通常由寫入服務本身提供），與實際匯出的資料之間有短暫空檔。若應用在這段時間（包括服務停止的過程中）仍會改變被比對的值，恢復後的第二次讀取就會不同，這份備份便沒有快照、還原時無法比對資料。只比對在這段空檔內不會變動的值，並確保所有寫入都來自 `writer_units`。
- **未套用的設定變更**：設定檔已修改但服務尚未重新啟動時，備份重新啟動服務會讓新設定生效；比對來自設定檔的值（例如示範的 `title`）因此改變時，同樣不會保存快照。這是管理者操作面的已知限制，見 [../backup.md](../backup.md)。

## 部署範本（`quadlet.template_dir`）

- 只在**全新部署**時使用（目標設備沒有此應用的任何 Quadlet 檔）：引擎以擁有者身分把範本寫入 `~/.config/containers/systemd/`（0644），執行 `systemctl --user daemon-reload`，再重建密鑰、設定檔、資料卷與資料庫。原位還原不使用範本，設備上現有的 Quadlet 檔保持不變。
- 全新部署前，目錄列出的資料卷、資料庫資料卷、範本 `.volume` 檔建立的資料卷、密鑰與設定檔都不可已存在，否則預檢失敗；因為全新部署失敗時會移除它建立的所有東西，既有的同名項目會一起被刪除。
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

規則：只在兩台實驗室設備測試，所有容器操作只經 `~/.woowbk-lab/bin/labpodman` 與 `tests/e2e/lab/` 的腳本，**不可在正式主機或正式應用上測試**；只用合成的測試資料，不可帶入正式密鑰。實驗室是共用的，安裝額外項目前先與其他測試者協調，測完移除。設備與腳本說明見 [tests/e2e/lab/README.md](../../tests/e2e/lab/README.md)。

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

## 審查清單

送審時附上目錄項目、部署範本、實驗室證據與測試紀錄。審查者逐項確認：

- [ ] **範圍完整**：應用所有持久狀態（資料庫、資料卷、密鑰、設定檔）都已列入；沒有不在支援範圍內的資料（主機資料夾掛載、整個資料夾）被忽略而宣稱完整；沒有列入不必要的敏感檔案。
- [ ] **擁有者**：一般帳號、非 root，與實際部署帳號一致。
- [ ] **服務**：`units` 順序正確；`writer_units` 涵蓋所有寫入者；資料庫服務不在其中、也不相依寫入服務；共用資料卷已評估。
- [ ] **PostgreSQL**：`container`、`unit`、`database`、`user`、`data_volume` 正確；容器內本機 socket 免密碼可用；執行個體沒有未宣告的資料庫；應用能接受物件由 `user` 擁有、角色不保留；版本 10 以上，映像以主版本固定。
- [ ] **映像**：`Image=` 可取得；`localhost/` 映像已在文件中註明跨設備需包含映像。
- [ ] **設定檔與密鑰**：路徑與名稱和應用實際使用的一致；設定檔位於 `.config/<id>/` 或 `.local/share/<id>/`；權限不超過 0644，放密碼的檔案為 0600；密鑰大小在限制內。
- [ ] **部署範本**：與正式部署一致、與主機無關、不含密鑰；全新部署後應用可正常啟動。
- [ ] **健康檢查**：反映應用真正可用；逾時足以涵蓋冷啟動；無副作用。
- [ ] **資料核對**：值穩定可重現，涵蓋資料庫、資料卷、設定檔與密鑰；唯讀、不需登入；已評估快照時間差。
- [ ] **相容性**：與先前版本的目錄項目相比，沒有讓需要還原的舊備份失去必要項目。
- [ ] **檔案與權限**：離線檢查通過；放到設備後，頁面沒有「備份設定提示」（`status` 的 `warnings` 是空的）。
- [ ] **實驗室證據**：同機、跨設備（不同 UID）、失敗回復、缺映像、中斷與洩漏檢查都通過；已記錄停機時間與版本。
- [ ] **正式主機**：第一次正式備份會暫停寫入服務，已排定維護時段並取得同意（見 [production-onboarding.md](production-onboarding.md)）。
