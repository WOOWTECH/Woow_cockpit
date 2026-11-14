# woowbk-inst：PostgreSQL「整個執行個體」模式的實驗室夾具

`woowbk-inst` 是「備份與還原」PostgreSQL **整個執行個體**模式（`"scope": "instance"`）的實驗室測試夾具，不是產品功能，
只部署在實驗室設備（`tests/e2e/lab/`）。它把單一資料庫模式保不住的東西放在同一個叢集裡，讓還原是否完整可以逐項比對：

* **類 Nextcloud**：資料庫 `nextcloud` 由角色 `oc_admin` 擁有，應用以 `oc_admin` 登入；它的密碼**只存在應用自己的資料卷**
  （`/data/config/dbpassword`，如同 Nextcloud 的 `config.php`）。還原後角色與密碼雜湊必須回來，應用才能連線。資料庫使用
  `vector`（pgvector 0.8）與 `pg_trgm`，有 HNSW 與 GIN 索引；`oc_admin` 屬於 NOLOGIN 角色 `nc_readonly`，並有資料庫層級的
  `search_path` 設定。
* **類 Odoo**：角色 `odoo`（CREATEDB、連線上限 50、`statement_timeout` 設定）擁有 `odoo_prod`（`LC_COLLATE C`、撤銷 PUBLIC 的
  CONNECT、資料庫設定與註解）與 `odoo_test` 兩個資料庫。

## 組成

| 項目 | 名稱 | 說明 |
| --- | --- | --- |
| Quadlet 範本 | `quadlet/woowbk-inst.network`、`woowbk-inst-db.container`、`woowbk-inst-app.container` | 實驗室以 root 安裝到 `/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-inst/quadlet/`（全新部署還原需要） |
| 資料庫容器 | `woowbk-inst-db` | `docker.io/pgvector/pgvector:pg16`；`POSTGRES_USER=ncadmin`（啟動時建立的管理帳號）；密碼來自密鑰 `woowbk-inst-db-password`；`--memory 256m` |
| 應用容器 | `woowbk-inst-app` | 沿用 `localhost/woowbk-demo-app:1`（woowbk-demo 的筆記應用），`DB_USER=oc_admin`、`DB_NAME=nextcloud`、密碼檔在資料卷內；`127.0.0.1:18092→8080`；`--memory 128m` |
| 資料卷 | `woowbk-inst-pgdata`（資料庫）、`woowbk-inst-files`（應用資料與密碼檔） | |
| 密鑰 | `woowbk-inst-db-password`、`woowbk-inst-app-key` | 部署時在設備內隨機產生，不輸出 |

沒有預先寫好的目錄項目：`tests/e2e/lab/strengthen_e2e.py instance` 先以擁有者身分部署並建立上述角色與資料庫，再用
`catalog-suggest` 產生草稿、選「整個執行個體」變體，補上部署範本位置、應用的 `/healthz` 與 `/api/summary` 核對後以
`catalog-install` 安裝到兩台設備（和管理者在「應用設定」頁做的一樣）。接著備份（資料庫持續執行）、破壞（改密碼、刪資料庫與
資料列、新增資料庫與角色）、原位還原與 dev-b 全新部署還原，逐項比對角色與密碼雜湊、成員關係、角色與資料庫設定、資料庫擁有者／
編碼／定序／權限／註解、資料內容、擴充套件版本、索引，以及 `odoo` 以原密碼登入、應用以 `oc_admin` 正常運作與資料摘要一致。
`strengthen_e2e.py cleanup` 會移除整個部署、目錄項目、範本與 pgvector 映像。
