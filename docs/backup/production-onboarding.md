# 正式應用接入備份的評估（下一階段）

> 2026-11-13 以唯讀方式盤點參考主機 `~/.config/containers/systemd/` 的 Quadlet 定義（未讀取任何應用機密內容，未變更服務）。同日依最終程式碼重新核對兩條規則：設定檔只能是應用自己的 `~/.config/<應用 ID>/` 或 `~/.local/share/<應用 ID>/` 之下的單一檔案；資料庫執行個體中有目錄未宣告的資料庫時，拒絕原位還原。設定檔路徑以各 Quadlet 的 `Volume=` 行核對；**沒有查詢正式資料庫**，各執行個體實際有哪些資料庫，要在接入時由預檢確認。目前**沒有任何正式應用已啟用備份**；每個應用都需要經過審查的目錄項目（catalog entry）與實驗室演練。

本文件說明哪些正式應用可以直接使用目前的 `quadlet-postgres` 方式、哪些需要先擴充，以及建議的接入順序。

## 目前方式已支援的結構

- 由同一個 Linux 帳號以 rootless Podman 執行的 Quadlet 應用。
- PostgreSQL 放在**具名資料卷**，備份時以 `pg_dump` 匯出**單一資料庫**。執行個體中除了這個資料庫，只能有 `postgres`、`template0`、`template1`；有其他資料庫（或無法列出）時，預檢失敗、原位還原被拒絕，因為重建資料卷會讓它們遺失。
- 其他資料放在**具名資料卷**，內容要能被 `podman volume import` 完整匯入（規則見 [app-catalog.md](app-catalog.md)）。
- 設定檔是應用自己的 `~/.config/<應用 ID>/` 或 `~/.local/share/<應用 ID>/` 之下的**單一檔案**。家目錄其他位置（例如 `~/.ssh`、`~/.gitconfig`、repository checkout 中的檔案）與整個資料夾都不能列入。
- Podman secrets。
- 備份時只暫停會寫入的服務（`writer_units`），資料庫保持執行以便匯出。
- 全新設備還原時，使用設備上已安裝、經審查的 Quadlet 範本；備份檔本身的 Quadlet 檔只作比對，不會直接安裝。

## 各應用盤點

「主機資料夾掛載」欄列出 Quadlet `Volume=` 中掛載的主機路徑（`~` 為應用擁有者家目錄）。

| 應用 | PostgreSQL | 其他資料 | 主機資料夾掛載 | 本機建置映像 | 評估 |
| --- | --- | --- | --- | --- | --- |
| LiteLLM | 1 個資料庫，具名資料卷 | 無 | 單一檔案 `~/.config/litellm/config.yaml` | 有 | **可直接接入**：資料庫、設定檔（應用 ID 用 `litellm` 時符合路徑規則）、5 個 secrets；跨設備需含映像 |
| n8n | 1 個資料庫，具名資料卷 | n8n 資料、Valkey 共 2 個資料卷 | 2 個單一檔案，都在 `~/.config/n8n/` | 無 | **可直接接入**：主服務、worker、webhook、兩個 runners、Valkey 都列為寫入服務（n8n 資料卷由主服務、worker、webhook 共用） |
| Hermes | 1 個資料庫，具名資料卷 | 2 個資料卷（含 Redis） | 無 | 有 | **可直接接入**；Redis 列為寫入服務 |
| Omnigent | 1 個資料庫，具名資料卷 | server、pi 共 2 個資料卷 | 無 | 有 | **大致可接入**：依 Quadlet 定義，pi 資料卷只有 omnigent-runner 掛載（`pi-web` 用的是另一個資料卷）；Quadlet 以外的容器沒有檢查 |
| EMQX | 無 | 資料、日誌 2 個資料卷 | 3 個單一檔案，都在 `~/.config/emqx/` | 無 | **可直接接入**（不需資料庫）；對外埠綁定在參考主機的區網 IP，只適合在已安裝 EMQX 的設備原位還原 |
| Odoo | 以 `postgres` 超級使用者執行，實際業務資料庫由 Odoo 建立，可能有多個 | filestore 資料卷 | 自訂模組**資料夾** `~/.local/share/odoo18/addons` | 有 | **需擴充**：目前只匯出單一資料庫，執行個體有其他資料庫時拒絕原位還原，所以有多個業務資料庫的 Odoo 無法使用；addons 是整個資料夾，目前的設定檔規則無法描述。需要擴充 1、2 |
| Headscale | 無（SQLite 在資料卷） | `headscale-data`（headscale 與 headplane 共用）、headplane 資料卷，另有執行期目錄用的 `headscale-run` | 設定**資料夾** `~/.config/headscale/headscale`（盤點時有 3 個檔案），加上入口與 headplane 的 3 個單一檔案，全部在 `~/.config/headscale/` 之下 | 有 | **可先以個別設定檔試接入，或等擴充 1**：6 個檔案都符合路徑規則，可逐一列入（容器以唯讀方式掛載它們）；但資料夾是整個掛載，日後新增的檔案不會被備份。對外埠位址需在目標設備調整 |
| Home Assistant | 無 | Matter 資料卷 | 整個設定資料夾 `~/homeassistant/config-preinstalled` | 有 | **需擴充**：主機資料夾備份；這個資料夾也不在 `.config/<應用 ID>/` 或 `.local/share/<應用 ID>/` 之下；資料量需實測 |
| Nextcloud | 資料庫資料放在**主機資料夾** | 無 | `~/.local/share/nextcloud-office/` 下的 html、data、postgres、redis 共 4 個資料夾；單一檔案 `~/.config/nextcloud/gateway.conf` | 有 | **需擴充**：主機資料夾備份、資料庫資料夾重建；資料夾（`nextcloud-office`）與設定檔（`nextcloud`）用了不同的目錄名稱，一個目錄項目只有一個應用 ID，接入前需統一；使用者檔案量大 |
| Immich | 資料庫資料放在**主機資料夾** | 模型快取 | `~/Woow_immich_docker_compose_all/` 下的相片庫與資料庫資料夾 | 無 | **需擴充**：同 Nextcloud；資料夾在 repository checkout 中，不在允許的目錄之下；相片庫可能非常大 |
| OpenDesign | 無 | 主資料卷（主服務與 terminal 共用）、mcp 資料卷，另有 mcp 與 nginx 共用的執行期資料卷 | 4 個單一檔案，都在 `~/.config/open-design/` | 有 | **可直接接入**（不需資料庫）；共用資料卷的服務都要列為寫入服務 |
| code-server | 無 | 3 個資料卷 | `~/Desktop`、`~/.ssh`、`~/.gitconfig`、`~/.local/bin` | 無 | **暫不建議**：這些路徑不在 `.config/<應用 ID>/` 或 `.local/share/<應用 ID>/` 之下，目前的格式無法列入；且涉及登入金鑰與整個桌面資料夾，需先決定備份範圍 |

說明：

- **有 PostgreSQL 的應用（LiteLLM、n8n、Hermes、Omnigent）**：評估假設各執行個體只有該應用的資料庫。這一點沒有查詢正式資料庫確認；若執行個體中還有其他資料庫，預檢會失敗、原位還原會被拒絕，需先處理才能接入。
- **沒有資料庫的應用（EMQX、OpenDesign、Headscale）**：目錄格式允許 PostgreSQL 項目為零，但這類應用目前**尚未實測**，接入時需先在實驗室演練。
- **設定檔權限**：盤點時多數設定檔是 0664。還原時一律以目錄宣告的權限（最多 0644）寫回，群組寫入權限會消失，審查時確認應用不需要它。
- 表中「可直接接入」指結構相符，仍須依下方步驟審查與演練。盤點範圍是上表 12 個應用；其他 Quadlet（例如各 `*-mcp-admin`、`pi-web`、`woow-cf-tunnel`）沒有評估。

## 需要的擴充（依優先順序）

1. **主機資料夾（bind mount）**：新增 `data_dirs` 類型。以應用擁有者身分匯出成 tar、還原時以新資料夾取代舊內容；路徑限制在擁有者家目錄內且需列在本機目錄，並需另訂路徑規則（目前設定檔只允許 `.config/<應用 ID>/` 與 `.local/share/<應用 ID>/`，Home Assistant、Immich 的資料夾在這之外）；排除快取等可重建內容；大小與空間預檢；匯出內容同樣要做巢狀 tar 檢查。Odoo、Headscale、Home Assistant、Nextcloud、Immich 需要。
2. **PostgreSQL 整個叢集模式**：`pg_dumpall --globals-only` 加上逐一匯出每個非範本資料庫；還原時重建叢集、還原角色與所有資料庫。Odoo 需要；目前遇到有多個資料庫的執行個體會拒絕原位還原，這個模式完成前不會遺失資料，但也無法還原。
3. **資料庫資料放在主機資料夾**：還原時以擁有者身分重建資料夾後讓 PostgreSQL 重新初始化，再匯入。Nextcloud、Immich 需要；也可評估改用具名資料卷。
4. **以 SQL 核對資料**：許多應用的 HTTP 介面需要登入，新增唯讀的資料筆數核對（例如表格列數），用於還原後比對。
5. **主機相關設定**：對外綁定 IP、網域等不能直接帶到另一台設備。正式應用的跨設備還原建議流程為「先在新設備安裝該應用套件，再原位還原資料」；只有範本與主機無關的應用才使用全新部署模式。

## 建議接入順序與每個應用的步驟

1. LiteLLM → 2. n8n → 3. Hermes → 4. Omnigent → 5. EMQX → 6. OpenDesign → 7. Odoo（擴充 1、2）→ 8. Headscale、Home Assistant（擴充 1；Headscale 也可在擴充前以個別設定檔先試）→ 9. Nextcloud、Immich（擴充 1、3，並評估資料量）。

每個應用：

1. 由該應用的 repository 提供目錄項目與（若需要）全新部署範本，依 [app-catalog.md](app-catalog.md) 審查：設定檔路徑符合規則、資料卷內容符合匯入規則、資料庫執行個體只有宣告的資料庫。
2. 在實驗室設備部署該應用的正式映像與測試資料，完成同機還原、跨設備還原、失敗回復三項演練。
3. 經同意後在正式主機執行第一次備份（寫入服務會短暫暫停，需選維護時段），確認備份檔可在實驗室設備完整驗證。
4. 若要以正式資料演練還原，需先同意將含客戶資料與應用機密的備份帶到實驗室設備，演練後刪除。
