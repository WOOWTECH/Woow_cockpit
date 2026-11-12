# woowtech Cockpit

Ubuntu 裝置管理介面的部署來源。將 woowtech 品牌樣式、既有服務管理、獨立「畫面參考」套件及安裝／回退工具集中維護，供其他設備重複部署。

**目前版本：2026.11.12.3。** 參考環境為 Ubuntu 24.04.4 LTS、Cockpit 362、cockpit-podman 124。此專案提供品牌介面及既有服務管理；應用服務、Quadlet、資料庫與客戶資料須由各自專案部署。

## 快速部署

在目標 Ubuntu 24.04 主機，以可使用 sudo 的帳號執行：

```bash
git clone https://github.com/WOOWTECH/Woow_cockpit.git
cd Woow_cockpit
bash scripts/bootstrap-ubuntu.sh --plan
sudo bash scripts/bootstrap-ubuntu.sh --apply
sudo python3 scripts/manage.py plan
sudo python3 scripts/manage.py install --service-owner "$(id -un)"
sudo python3 scripts/manage.py verify
```

開啟 `https://<設備 IP>:9090`，使用該設備的 Linux 帳號登入。安裝不建立共用帳密、不更改既有密碼。若已有 Cockpit 362 以上，可略過 bootstrap，先查看 `plan`。

`--service-owner` 指定實際部署 rootless 服務的 Linux 帳號；若與目前帳號不同，請替換成正確名稱。登入後開啟管理員存取權限，從「系統 → 服務管理」查看該使用者的服務、容器與日誌，並啟動／停止／重新啟動服務。之後更新時省略此參數會保留設備設定。詳見[服務管理](docs/services.md)。

安裝後請登出再登入並強制重新整理，讓 Cockpit 更新套件清單和瀏覽器快取。登入後「工具 → 畫面參考」對應 `/woowtechpreview`。防火牆、可信憑證及帳號權限由設備管理者依環境設定，見[部署說明](docs/deployment.md)。

## 包含什麼

| 項目 | 現況 |
| --- | --- |
| 登入、側欄、頁面底色 | 全白、官方 SVG、主題藍 `#6183FC`；沒有背景照片 |
| 元件樣式 | 桌面登入卡片縮為75%、登入 Logo 放大10%；20px 卡片、12px 輸入框、本地字型、保留原生警示色與終端機配色 |
| 原生頁面 | 主機、日誌、儲存、網路、Podman、帳號、服務、應用、更新、終端、硬體、指標 |
| 排版修正 | 總覽斷點、長名稱、映像清單區域捲動、手機帳號／服務、指標卡片 |
| 畫面參考套件 | 17 個截圖位置、排版研究紀錄；缺少本機截圖時顯示提示 |
| 服務管理套件 | 本機系統及指定使用者的 systemd 服務；狀態、搜尋、分頁、PID／記憶體／累計 CPU／相依服務、日誌、啟動／停止／重新啟動 |
| Podman／Quadlet | 列出指定擁有者容器；Quadlet 透過 systemd 控制，停止後仍列出服務；原生124版 All 自動載入設定的擁有者，一般容器沿用原生建立／啟停／刪除 |
| 部署管理 | 變更預覽、逐檔備份、重複安裝、SHA-256 檢查、拒絕覆蓋較新修改的回退 |
| 客戶應用備份還原中心 | **尚未實作**；本專案的 rollback 只還原此次介面安裝的檔案 |
| GitHub 應用更新／Supervisor | **尚未實作**；目前由管理者手動部署 |

原生頁面能否管理設備，仍取決於權限及 NetworkManager、UDisks、Podman、PackageKit 等後端。畫面套用成功不代表所有管理情境均已驗收。PCP 歷史圖、套件更新完成和整機災難復原不在此次完成範圍。

原生 Podman 整合只套用至已驗證的124版；較新版本保留其原生程式，跨使用者管理仍可使用「服務管理」。[修補來源與重建方式](native/podman/README.md)。

## 其他設備導入前先看

- [部署與 rootless Podman](docs/deployment.md)
- [服務管理與權限範圍](docs/services.md)
- [檔案結構、Cockpit 套件機制](docs/architecture.md)
- [更新、驗證、回退與故障排查](docs/operations.md)
- [參考主機現況與驗證範圍](docs/current-state.md)
- [可重現測試與本機截圖](docs/testing.md)
- [後續備份還原功能](docs/roadmap.md)
- [第三方授權與品牌資產](NOTICE.md)

## 開發驗證

部署本身只需 Python 3 標準函式庫；瀏覽器驗證才需要 Node.js 和 Chromium。

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_source.py
bash -n scripts/bootstrap-ubuntu.sh scripts/build-podman.sh
npm ci
npx playwright-core install chromium
npm test
```

目前提供 Ubuntu 24.04 的 bootstrap。較新 Cockpit 可安裝，但須重新驗證 PatternFly 類別與排版；本專案不將 362 宣稱為最新版本，也不固定安裝舊套件。出貨請記錄所用 commit 與實際套件版本。

相關基礎系統紀錄：[Woow_ubuntu_version_control](https://github.com/WOOWTECH/Woow_ubuntu_version_control)。
