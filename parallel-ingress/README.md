# 同一台主機的 WOOW／Apporo 雙入口

`parallel-ingress` 在保留原 WOOW 入口的主機上，增加可選的 Apporo Cockpit／PWA／Pi 呈現。兩個入口管理**同一份主機服務、備份引擎、Podman 應用及原生 Pi 資料**。它不安裝第二組 47 個應用容器，也不建立第二個租戶、服務 owner 或獨立備份引擎；任一入口的管理操作都會影響同一台主機。

Apporo 使用一個 `apporo-cockpit-pwa` 前端容器及兩個 root systemd Pi gateway units。已有同名 Apporo 樣板入口時，沿用其 Quadlet 名稱原地更新。原 Cockpit 登入、管理員提權和 Pi 自己的密碼保護繼續適用。

## 1. 固定來源並確認共同後端

使用交付時記錄的、經審查的完整 Cockpit commit，將獨立 checkout 固定在該 commit；不可以當下浮動的 `main` 代替發行材料。在這份 checkout 根目錄操作，並記錄：

```bash
git rev-parse HEAD 'HEAD^{tree}'
git status --porcelain
```

工作樹必須乾淨，所有程式與文件已 commit。installer 會記錄 source commit／tree 並拒絕 dirty source；不要直接修改 checkout 裡的樣板來放設備設定，應將設定複製到後述 root 目錄。本頁不提供尚未完成驗收／合併的最終 SHA；以實際交付材料為準。

共同後端必須先安裝**同一份固定來源**：service manager helper、backup helper、所有 backup engine Python 模組的內容及模組清單都必須一致。缺少、修改或多出模組都會拒絕部署，不能只看 UI 版本號相同。

若需要同步共同後端，先用同一 checkout 的主要安裝器預覽，再保留現有品牌執行安裝與驗證：

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 python3 scripts/manage.py plan
sudo env PYTHONDONTWRITEBYTECODE=1 python3 scripts/manage.py install
sudo env PYTHONDONTWRITEBYTECODE=1 python3 scripts/manage.py verify
```

此處省略 `--brand` 會保留已安裝品牌，省略 `--service-owner` 會保留已有 owner 設定；WOOW 主入口仍應是 woowtech。不要為新增 Apporo 入口而將主要安裝器設為 `--brand apporo`。共同安裝器原有的服務與備份 timer 語義仍適用；共同後端同步與入口新增分別驗證。本流程以已有共同套件及 owner 設定的主機為前提，新主機先依[主安裝說明](../README.md)建立共同層。

還需要已由 [`pi-web-integration/install.sh`](../pi-web-integration/README.md) 安裝的 `woowpiweb` Cockpit package，以及正在運行、已啟用自身密碼保護的原生 Pi Web。主要 `scripts/manage.py install` 不會代裝這個獨立 Pi package。若缺少，先依該整合文件使用這台主機原有的 LAN／VPN／public 參數安裝；不要為第二入口猜測參數或重設主入口的網路設定。

部署 owner 的 rootless Podman、systemd user manager 與 `~/.config/containers/systemd/` 必須已可用。`node_path` 只允許 `/usr/bin/node` 或 `/usr/local/lib/woow-node/node`，執行檔須由 root 擁有且 group／other 不可寫入；沿用 Pi 整合要求的 Node 版本，不使用一般帳號家目錄中的 Node。

## 2. 建立 root-owned instance 設定

使用 [config.example.json](config.example.json) 作為格式範例。`operator`、`apporo.example.test` 都是佔位值，必須換成此主機既有的服務 owner 及正式 HTTPS origin。檔案不放密碼、Token、Cookie、Cloudflare credentials 或任何網站私密資料。

第一次建立設定時：

```bash
sudo install -d -o root -g root -m 0755 /etc/cockpit/parallel-ingress-config
sudo install -o root -g root -m 0600 parallel-ingress/config.example.json \
  /etc/cockpit/parallel-ingress-config/apporo.json
sudoedit /etc/cockpit/parallel-ingress-config/apporo.json
```

已有設定時直接 `sudoedit`，不要用樣板覆寫。傳入的 config 必須是絕對路徑的一般檔案；從 `/` 到檔案的各層祖先都須由 root 擁有、group／other 不可寫入、不可經過 symlink。把家目錄或 `/tmp` 下的檔案改成 root owner，仍不符合祖先目錄要求。

| 欄位 | 範例／預設 | 意義 |
| --- | --- | --- |
| `schema` | `1` | 設定格式版本 |
| `instance` | `apporo` | 入口識別；保留的 `woow` 名稱不可使用 |
| `brand` | `apporo` | 此入口呈現；不改全域品牌 |
| `owner` | `operator` | 已有 rootless Podman owner，不可為 root |
| `public_origin` | `https://apporo.example.test` | 精確 HTTPS DNS origin，不含路徑、port、尾斜線或登入資訊 |
| `listen_port` | `29092` | 綁定 `127.0.0.1` 的主要前端入口 |
| `compatibility_port` | `null` | 可省略；需沿用舊 public 轉送埠時可設為例如 `18000` |
| `pi_public_port` | `19096` | 僅 loopback 的 public Pi gateway |
| `pi_local_port` | `19097` | 僅 loopback 的本機預覽 Pi gateway |
| `cockpit_port` | `9090` | 已有 Cockpit backend 埠；填主機實際值 |
| `pi_upstream_port` | `30141` | 同一個原生 Pi Web upstream 埠 |
| `node_path` | `/usr/bin/node` | 已驗證的 root-owned Node |
| `image` | 樣板中的 nginx registry digest | immutable image reference；不能改用浮動 tag |

各個設定埠必須是 1024–65535 的不同整數；新增 listener 埠須可用。`image` 釘選 registry manifest digest，不能換成 image config ID。installer 會以 owner 的 Podman 取得該固定映像並執行 `nginx -t`；因此仍需要取得映像的條件，不宣稱完全離線安裝。

## 3. Plan、安裝與驗證

從同一份固定且乾淨的 checkout 執行：

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 python3 parallel-ingress/manage.py plan \
  --config /etc/cockpit/parallel-ingress-config/apporo.json
sudo env PYTHONDONTWRITEBYTECODE=1 python3 parallel-ingress/manage.py install \
  --config /etc/cockpit/parallel-ingress-config/apporo.json
sudo env PYTHONDONTWRITEBYTECODE=1 python3 parallel-ingress/manage.py verify --instance apporo
```

`plan` 讀取設定、檢查來源乾淨及後端 bytes parity，輸出來源與預定寫入位置；不執行安裝，也不代表 public 路由或瀏覽器功能已驗收。`install` 產生獨立品牌檔案、驗證 nginx，使用 transaction journal 切換入口並執行驗證。後端不一致時先處理共同層，不能跳過 parity。

root 產物位於 `/etc/cockpit/parallel-ingress/apporo/releases/<release>/`，`current` 指向目前 release，`transactions/` 保存入口交易。使用者 Quadlet 是 `apporo-cockpit-pwa.container`；兩個 root units 為 `cockpit-apporo-pi-public.service` 與 `cockpit-apporo-pi-local.service`。這些入口 gateway 使用同一 Cockpit／Pi upstream，不建立新帳號、資料庫或應用 secrets。

安裝器會在 Cockpit `Origins` 新增精確的 public／loopback origin，保留原有 WOOW origins；需要時會重啟 Cockpit 服務。proxy 保留實際 browser `Origin`，不偽造來源來繞過驗證。

`verify` 檢查 release／後端清單與雜湊、檔案權限、Quadlet、兩個 Pi units、服務狀態及 loopback 登入頁。仍須另測 WOOW 與 Apporo 的登入、管理員提權、服務／備份頁和 Pi 獨立登入；HTTP 成功不等同真實備份還原或外部模型對話成功。

## 本機安全預覽與 public HTTPS

本機入口是 `http://127.0.0.1:29092`。保留這個精確的 Host／port；不要替換成 LAN IP 或 `localhost`。loopback 可用於本機安全預覽，仍需 Cockpit 與 Pi 各自的登入。它沒有監聽 LAN／VPN 位址，不能直接用 `http://<LAN-IP>:29092` 開啟。

遠端管理可透過 SSH 將相同本機埠轉送到主機 loopback，然後在自己的瀏覽器開啟上述 `127.0.0.1` 網址：

```bash
# 換成目標主機的 SSH 帳號與名稱；本機 29092 必須未被使用。
ssh -N -L 127.0.0.1:29092:127.0.0.1:29092 operator@appliance.example.test
```

public 入口由既有、受信任的 Cloudflare HTTPS 路由連到該主機的 `127.0.0.1:29092`，保留正式 Host 與受信任 proxy 提供的 `X-Forwarded-Proto: https`。browser 使用 config 的完整 `public_origin`，不直接公開後端或兩個 Pi gateway ports。DNS、TLS、Tunnel 與 Access 路由須另行配置及驗證；這個 installer 不建立 Cloudflare 路由，也不修改任何 Cloudflare Access policy。

若既有 public 轉送仍指向 `127.0.0.1:18000`，可明確設定 `compatibility_port: 18000` 保留別名。它只接受相同正式 public Host／HTTPS 條件，不提供第二個本機、LAN 或 VPN 預覽入口；本機預覽一律使用 `listen_port`。

**公開入口的 OTP／Cloudflare Access 是獨立授權層。若原本要求 OTP，此功能不會移除、停用或繞過它。** 通過 Access 後仍須完成 Cockpit 和 Pi 的登入；本機預覽通過不能當成 public Access 已驗收。

## 回退範圍

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 python3 parallel-ingress/manage.py rollback --instance apporo
```

rollback 依該 instance 的 transaction journal 還原入口 release、Quadlet、Pi units、服務狀態及受管理的 Cockpit 設定，可能重啟相關入口／Cockpit。它只回退這次 UI／入口設定交易，不還原應用資料、對話、備份檔、Secret、共同 engine 或全域品牌；也不回退 Cloudflare policy／DNS／Tunnel。若受管理檔案在安裝後被另行修改，或前一 release 已不符合共同後端，必須先處理差異，不能覆寫檔案硬退。

並行入口與共同後端升級應使用相容來源並分開記錄驗收。保留既有設備資料和入口，不代表提供租戶隔離或零中斷保證；本文件與樣板本身也不代表特定設備已完成實機驗收。
