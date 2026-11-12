# cockpit-podman 124：設定擁有者整合

2026.11.12.3 加入，修補 `Owner → All` 不載入已部署應用帳號，以及首次指定 UID／權限切換／舊連線回呼的時序問題。既有原生容器功能、API 與 Cockpit 權限機制沿用上游。

## 來源

| 內容 | 固定版本 |
| --- | --- |
| cockpit-podman | tag `124`，commit `a6b82a69d66404d91c47eb811a047b5e433bee41` |
| Cockpit 共用 `pkg/lib` | `92e0108df1034207bcf7852c7747707d7da044ac`，由該版 Makefile 指定 |
| npm 依賴 | 封存中的 `package-lock.json`；以 Node.js 22 建置 |

`source-124.tar.gz` 包含未修改的上游建置原始碼、所需共用元件及 lockfile。排除與建置無關的上游測試及 Git metadata；沒有主機設定、客戶資料、node_modules 或認證。對上游的修改在 `upstream.patch`，新增整合在 `managed-owners.js`。

上游：[cockpit-podman124](https://github.com/cockpit-project/cockpit-podman/tree/124)、[Cockpit 共用元件](https://github.com/cockpit-project/cockpit/tree/92e0108df1034207bcf7852c7747707d7da044ac/pkg/lib)。

## 重建與部署

```bash
# repository 根目錄，需 Node.js 22、npm、tar、patch 和網路
bash scripts/build-podman.sh
node --test tests/managed-owners.mjs
sudo python3 scripts/manage.py plan
sudo python3 scripts/manage.py install
sudo python3 scripts/manage.py verify
```

建置在暫存目錄解壓來源、套用修補，以 lockfile 安裝依賴並產生 production bundle。`dist/index.js.gz` 是提供給設備的壓縮 JS。原生 HTML、CSS 與翻譯由 Ubuntu 套件提供。本輪已執行來源封存的完整重建。

安裝器僅針對 dpkg 的 cockpit-podman124 套用 bundle，125及其他版本保留原生程式。每次替換均有安裝交易備份；APT 更新可能覆寫此檔案，須按新版本重新驗證。`--no-services` 不套用整合，也不自動還原之前已安裝的版本。

## 權限與範圍

透過既有 root helper 的 `scopes` 讀取 `/etc/woowtech-cockpit/services.json` 所設定的帳號。只有 Cockpit 管理員模式可以跨使用者連接；All 不代表任意系統帳號。一般容器沿用原生部署與控制；其他使用者的 Quadlet 啟停使用「服務管理」。

## 授權

Cockpit／cockpit-podman 與本目錄的整合、修補依 **LGPL-2.1-or-later** 提供。相應建置來源隨此目錄提供，沒有以封閉 bundle 取代來源。原始作者及第三方著作權保留。`dist/index.js.LEGAL.txt` 包含 bundle attribution，`dist/licenses/` 包含 LGPL、GPL 文字與所包含 npm 模組的授權。本授權不涵蓋 WOOWTECH 商標。
