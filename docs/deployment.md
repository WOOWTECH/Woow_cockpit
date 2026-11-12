# 部署

## 前置條件

- Ubuntu 24.04、Python 3、Git、可使用 sudo 的 Linux 帳號。
- APT 已配置 Ubuntu backports。`bootstrap-ubuntu.sh --plan` 不變更設備；`--apply` 更新套件索引、安裝 Cockpit 與管理擴充、啟用 `cockpit.socket`。
- 套件包括 cockpit、cockpit-podman、cockpit-storaged、cockpit-networkmanager、cockpit-packagekit。依賴由 APT 處理。
- 不自動切換既有網路管理方式、安裝 firewalld、啟用 PCP、重啟應用服務或更新容器。

依 README 執行後，用 `systemctl status cockpit.socket` 確認入口。允許的管理網段需能連到 TCP 9090；防火牆規則應限制到實際管理網段。瀏覽器第一次可能遇到自簽憑證提示，可依 [Cockpit TLS 文件](https://cockpit-project.org/guide/latest/https.html) 安裝設備的可信憑證。

## 安裝選項

```bash
# 只查看將更動哪些檔案
sudo python3 scripts/manage.py plan
# 安裝品牌、服務管理與畫面參考套件
sudo python3 scripts/manage.py install
# 指定實際應用服務擁有者，啟用跨使用者服務管理
sudo python3 scripts/manage.py install --service-owner <服務帳號>
# 僅管理品牌；保留現有擴充套件檔案，但不再追蹤
sudo python3 scripts/manage.py install --no-preview --no-services
# 另外匯入此設備已擷取的截圖
sudo python3 scripts/manage.py install --screenshots .local/screenshots
```

`--no-preview` 與 `--no-services` 分別停止安裝及追蹤對應套件，磁碟上原有檔案仍保留；同時指定才只追蹤品牌和原生樣式入口。它們不是解除安裝選項。回退方式見 operations。

`--root /path/to/staged-ubuntu` 必須放在子指令前，可對具 dpkg 狀態檔的離線根目錄做封裝驗證。套件安裝及服務啟用仍需在目標系統處理。

## 帳號與 rootless Podman

Cockpit 使用系統帳號登入，管理員授權沿用 Cockpit／sudo／polkit 的原有流程。此專案沒有預設帳號、沒有內建密碼，亦不修改 PAM 或 root 登入限制。

Rootless Podman 的映像和容器屬於個別 Linux 使用者。另一個管理帳號登入後看到「0 containers」，可能是選到不同使用者的儲存空間。先確認服務擁有者：

```bash
# 以實際部署服務的使用者執行
podman ps
systemctl --user status podman.socket
```

可直接用服務擁有者登入 Cockpit；需要跨使用者管理時，先取得管理員權限，再在 Podman 頁選正確擁有者。若該使用者需要 API socket，可由該使用者執行 `systemctl --user enable --now podman.socket`。需要登出後維持使用者服務時，管理者可執行 `sudo loginctl enable-linger <服務使用者>`。這些動作應依設備用途設定，安裝品牌不會代為執行。

**跨使用者的 Quadlet 啟停請使用新增的「服務管理」。** 原生 Podman124 的其他使用者選單依賴運行中容器發現，且限制其他使用者的 Quadlet 控制；原生 Services 的 User 只代表登入者。完整限制與新入口見 [services.md](services.md)。

不要為了顯示容器而重建另一份 Podman 儲存區，也不要更改原有 Quadlet 的擁有者。原生 cockpit-podman 管理的是容器；應用層級的備份順序、資料庫一致性與多容器還原仍需各應用的流程。

## 反向代理

直接使用 9090 不需要本專案的代理設定。已有反向代理時，依 `examples/cockpit.conf.reverse-proxy` 填入自己的來源，合併到現有 `/etc/cockpit/cockpit.conf`，不要直接覆蓋整份檔案。代理須支援 WebSocket 並正確傳遞協定標頭。未在本次測試新的代理環境。

官方參考：[Ubuntu 安裝](https://cockpit-project.org/running.html)、[Cockpit 設定](https://cockpit-project.org/guide/latest/cockpit.conf.5.html)。
