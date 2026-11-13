# woowbk-demo：備份與還原示範應用（測試夾具）

`woowbk-demo` 是「備份與還原」功能的測試夾具，不是產品功能。它刻意把一個 rootless Podman
Quadlet 應用的狀態分散在**資料庫、資料卷、Podman 密鑰與設定檔**四處，讓備份／還原是否完整
可以用一個 `/api/summary` 結果直接比對。所有名稱都以 `woowbk-` 開頭，只部署在實驗室設備
（`tests/e2e/lab/`）；正式主機只在負責人同意的實測中例外部署，測完可移除（見 `docs/current-state.md`）。不可用來測試正式應用的資料。

## 組成

| 項目 | 名稱 | 說明 |
| --- | --- | --- |
| 受信任目錄設定 | `catalog.json` | 與 `docs/backup/CONTRACT.md` 第 4 節範例逐欄相同；安裝為 `/etc/woowtech-cockpit/backup/apps/woowbk-demo.json`（root 0644） |
| Quadlet 範本 | `quadlet/woowbk-demo.network`、`woowbk-demo-db.container`、`woowbk-demo-app.container` | 安裝為 `/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet/`（root 0644）；部署時複製到 `~appowner/.config/containers/systemd/` |
| 使用者服務 | `woowbk-demo-network.service`、`woowbk-demo-db.service`、`woowbk-demo-app.service` | 由 Quadlet 產生；`WantedBy=default.target`，搭配 linger 開機自動啟動 |
| 網路 | `woowbk-demo` | `NetworkName=woowbk-demo`，容器以名稱互相解析（aardvark-dns） |
| 資料庫容器 | `woowbk-demo-db` | `docker.io/library/postgres:16-alpine`；`POSTGRES_USER=notes`、`POSTGRES_DB=notes`；密碼來自密鑰（`type=env`）；`HealthCmd=pg_isready`；`--memory 256m` |
| 應用容器 | `woowbk-demo-app` | `localhost/woowbk-demo-app:1`（`app/Containerfile`：python:3.12-alpine + pg8000 1.31.2，標準函式庫 HTTP）；`127.0.0.1:18090→8080`；`--memory 128m` |
| 資料卷 | `woowbk-demo-pgdata`（資料庫）、`woowbk-demo-files`（上傳檔案，掛在 `/data`） | 停止服務不會刪除（Quadlet `--rm` 只移除容器） |
| 密鑰 | `woowbk-demo-db-password`、`woowbk-demo-app-key` | 以 `podman secret create NAME -` 由標準輸入建立；應用以 `/run/secrets/<名稱>` 讀取原始位元組 |
| 設定檔 | `~/.config/woowbk-demo/app.env`（0600，目錄 0700） | `APP_TITLE=…`，以 `EnvironmentFile=%h/.config/woowbk-demo/app.env` 載入 |

應用映像只存在於建置它的設備（`localhost/…` 無法下載），這正是「備份未含映像時，在沒有此映像的
設備預檢必須失敗」情境（S3）所需的條件。

## API

| 方法與路徑 | 結果 |
| --- | --- |
| `GET /healthz` | 資料庫可連線**且** `/data` 可寫入時回 200 `{"ok":true,"database":true,"data_writable":true}`，否則 503（同結構，指出哪一項失敗） |
| `GET /api/summary` | `{"notes","files","digest","title","signatures_valid"}`，見下節 |
| `GET /api/notes` | `{"notes":[{"id","title","body","signature","created"}]}`（最多最新 1000 則） |
| `POST /api/notes` | JSON `{"title":"…","body":"…"}`（只接受這兩個欄位；title 1–200 字、body ≤ 64 KiB）→ 201 |
| `GET /api/files` | `{"files":[{"name","size","sha256"}]}` |
| `POST /api/files?name=<名稱>` | 原始位元組本文（≤ 16 MiB，需 `Content-Length`）→ 201 `{"name","size","sha256"}`；名稱 `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` |
| `GET /api/files/<名稱>` | 檔案內容（`application/octet-stream`） |

錯誤回應為 `{"error":"<繁體中文說明>"}`（400／404／405／411／413／503）。API 沒有身分驗證，只發佈在
設備的 127.0.0.1；它是測試夾具，不可對外開放。

### `/api/summary` 的定義

* `notes`：`notes` 資料表筆數；`files`：`/data/files` 內一般檔案數（略過 `.upload-*` 暫存檔、目錄與符號連結）。
* `digest`：下列標準 JSON 的 SHA-256（`sort_keys`、分隔符 `(',', ':')`、`ensure_ascii=False`、UTF-8）：
  `{"files": [[名稱, sha256], …依名稱排序], "notes": [[id, title, body, signature], …依 id 排序]}`。
* `title`：環境變數 `APP_TITLE`（來自設定檔）。
* `signatures_valid`：以**目前**的 `woowbk-demo-app-key` 原始位元組重新計算每則筆記的
  HMAC-SHA256（訊息為 `[id, title, body]` 的緊湊 JSON），全部相符才是 `true`。密鑰只要差一個位元組
  （包括多一個結尾換行）就會變成 `false`，因此能偵測密鑰還原錯誤。

`tools/check.py` 會從 `/api/notes` 與 `/api/files` 在用戶端重新計算 digest，證明上述定義。

## 手動部署（以 appowner 身分，不經過備份引擎）

在實驗室中執行 `tests/e2e/lab/deploy-demo.sh a`，它依序做以下步驟（亦可在設備內手動執行，
`woowbk-owner` 會以 `runuser` 和固定環境切換成 appowner，與引擎相同）：

```bash
# 設備內以 root 執行；/opt/woowbk-demo 為本目錄的唯讀副本
woowbk-owner podman pull docker.io/library/postgres:16-alpine
woowbk-owner podman build --memory 512m -t localhost/woowbk-demo-app:1 /opt/woowbk-demo/app
woowbk-owner sh -c 'mkdir -p -m 0700 ~/.config && mkdir -p ~/.config/containers/systemd &&
  install -m 0644 /opt/woowbk-demo/quadlet/* ~/.config/containers/systemd/'
woowbk-owner systemctl --user daemon-reload
woowbk-owner python3 /opt/woowbk-demo/tools/seed.py --notes 12 --files 4
```

`seed.py` 會：建立兩個隨機密鑰（已存在則保留，值只經由標準輸入傳給 podman，不出現在參數、
環境或輸出）、寫入設定檔（指定 `--title` 且與現值不同時重寫並重新啟動應用）、啟動服務、等待
`/healthz`，再新增 N 則筆記（含多位元組 UTF-8，例如 `𠮷`）與 M 個隨機檔案，最後輸出摘要。
再次執行並使用較小的數字或新的 `--title`，即可在備份後「變更資料」。
`--notes 0 --files 0 --no-start` 只輸出目前摘要。

## 驗證工具

```bash
woowbk-owner python3 /opt/woowbk-demo/tools/check.py                # 唯讀：所有端點、檔案雜湊、digest、錯誤輸入
woowbk-owner python3 /opt/woowbk-demo/tools/check.py --write        # 另新增一則筆記與一個檔案
woowbk-owner python3 /opt/woowbk-demo/tools/check.py --db-outage    # 暫停資料庫：/healthz 必須變 503，恢復後 200
woowbk-owner python3 /opt/woowbk-demo/tools/check.py --stop-start   # 停止服務：容器消失、資料卷與密鑰保留；重啟後摘要相同
```

離線單元測試（不需容器）：`python3 -B -m unittest discover -s tests/e2e -p 'test_*.py' -v`。

## 已知限制

* 容器內以 root 執行（rootless Podman 對應到主機上的 appowner）；資料卷內檔案擁有者為容器 root。
* 每個請求建立一個資料庫連線；只適合測試資料量。
* 應用啟動時自動建立 `notes` 資料表（`CREATE TABLE IF NOT EXISTS`）。還原時引擎先移除資料庫資料卷、
  啟動資料庫、`pg_restore`，最後才啟動應用，因此不會與還原內容衝突；若有人先在空資料庫啟動應用，
  再對同一個資料庫 `pg_restore --single-transaction`，會因資料表已存在而失敗。
* PostgreSQL 主版本由映像標籤 `16-alpine` 決定（2026-11-13 實測為 16.15）。
