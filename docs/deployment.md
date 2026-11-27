# 部署

## 前置條件

- Ubuntu 24.04、Python 3、Git、可使用 sudo 的 Linux 帳號。
- APT 已配置 Ubuntu backports。`bootstrap-ubuntu.sh --plan` 不變更設備，只列出各套件是否已安裝；`--apply` 更新套件索引、安裝 Cockpit 與管理擴充、安裝備份工具、啟用 `cockpit.socket`。
- 套件包括 cockpit、cockpit-podman、cockpit-storaged、cockpit-networkmanager、cockpit-packagekit（來自 backports），以及「備份與還原」需要的 `age`（加密）、`zstd`（壓縮），和讀取上傳的 Home Assistant 備份需要的 `python3-nacl`（解開 2026 年 3 月以後的 HA 加密備份）與 `python3-cryptography`（解開較舊的 HA 加密備份）。這些都來自一般套件庫，`age` 位於 universe。套件庫找不到它們時，`--apply` 會在安裝任何套件前停止並提示啟用 universe。重複執行沒有副作用：備份用的四個套件都在時，連不到套件庫也不會擋；真的缺套件又裝不上才停止並列出名稱。這只指備份用的四個套件；Cockpit 的五個套件照舊，需要下載時仍要連得到套件庫。依賴由 APT 處理。實驗室驗證使用 age 1.1.1、zstd 1.5.5、python3-nacl 1.5.0、python3-cryptography 41.0.7。
- 不自動切換既有網路管理方式、安裝 firewalld、啟用 PCP、重啟應用服務或更新容器。

依 README 執行後，用 `systemctl status cockpit.socket` 確認入口。允許的管理網段需能連到 TCP 9090；防火牆規則應限制到實際管理網段。瀏覽器第一次可能遇到自簽憑證提示，可依 [Cockpit TLS 文件](https://cockpit-project.org/guide/latest/https.html) 安裝設備的可信憑證。

## 安裝選項

```bash
# 只查看將更動哪些檔案
sudo python3 scripts/manage.py plan
# 安裝品牌、服務管理、備份與還原及畫面參考套件
sudo python3 scripts/manage.py install
# 指定實際應用服務擁有者，啟用跨使用者服務管理
sudo python3 scripts/manage.py install --service-owner <服務帳號>
# 僅管理品牌；保留現有擴充套件檔案，但不再追蹤
sudo python3 scripts/manage.py install --no-preview --no-services --no-backup
# 不安裝或不再更新「備份與還原」套件
sudo python3 scripts/manage.py install --no-backup
# 另外匯入此設備已擷取的截圖
sudo python3 scripts/manage.py install --screenshots .local/screenshots
```

`--no-preview`、`--no-services` 與 `--no-backup` 分別停止安裝及追蹤對應套件，磁碟上原有檔案仍保留且不再更新；三者同時指定才只追蹤品牌和原生樣式入口。它們不是解除安裝選項。回退方式見 operations。

`--backup-demo-catalog` **只用於實驗室設備**：另外安裝示範應用 `woowbk-demo` 的受信任目錄項目與 Quadlet 範本（需要備份套件，不能與 `--no-backup` 併用），安裝時會印出提醒。**不可用在客戶設備。** 之後不加此參數重新安裝時，安裝器不再追蹤示範項目，但不會刪除它，頁面仍會列出示範應用；誤裝時由 root 刪除 `/etc/woowtech-cockpit/backup/apps/woowbk-demo.json` 與 `/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/`，或回退加入它的那次安裝。

`--root /path/to/staged-ubuntu` 必須放在子指令前，可對具 dpkg 狀態檔的離線根目錄做封裝驗證。套件安裝及服務啟用仍需在目標系統處理：排程備份的兩個單元會寫到該根目錄下，但不會執行任何 `systemctl`，安裝器會提示在目標系統執行 `systemctl daemon-reload` 與 `systemctl enable --now woowtech-cockpit-backup-schedule.timer`。

## 帳號與 rootless Podman

Cockpit 使用系統帳號登入，管理員授權沿用 Cockpit／sudo／polkit 的原有流程。此專案沒有預設帳號、沒有內建密碼，亦不修改 PAM 或 root 登入限制。

Rootless Podman 的映像和容器屬於個別 Linux 使用者。另一個管理帳號登入後看到「0 containers」，可能是選到不同使用者的儲存空間。先確認服務擁有者：

```bash
# 以實際部署服務的使用者執行
podman ps
systemctl --user status podman.socket
```

可直接用服務擁有者登入 Cockpit；需要跨使用者管理時，先取得管理員權限。安裝本專案的124版整合後，Podman 頁的 Owner → All 會載入設定的服務擁有者，也可選單一帳號。Show 是容器狀態篩選。若該使用者需要 API socket，可由該使用者執行 `systemctl --user enable --now podman.socket`。需要登出後維持使用者服務時，管理者可執行 `sudo loginctl enable-linger <服務使用者>`。這些動作應依設備用途設定，安裝品牌不會代為執行。

**跨使用者的 Quadlet 啟停請使用新增的「服務管理」。** 本專案修正原生 Podman124 的擁有者探索，但保留其他使用者的 Quadlet 控制限制；原生 Services 的 User 只代表登入者。完整限制與新入口見 [services.md](services.md)。

不要為了顯示容器而重建另一份 Podman 儲存區，也不要更改原有 Quadlet 的擁有者。原生 cockpit-podman 管理的是容器；應用層級的備份順序、資料庫一致性與多容器還原由「備份與還原」頁處理，但只適用於已安裝受信任目錄項目的應用（見 [backup.md](backup.md)），其他應用仍需各自的流程。

## 備份與還原套件

預設的 `install` 會安裝「備份與還原」頁、備份引擎與 root helper，並建立空的應用目錄資料夾：

| 項目 | 位置 |
| --- | --- |
| Cockpit 頁面（`woowtechbackup`） | `/usr/local/share/cockpit/woowtechbackup/` |
| 備份引擎與版本檔 | `/usr/local/lib/woowtech-cockpit-backup/` |
| root helper | `/usr/local/libexec/woowtech-cockpit-backup` |
| 受信任應用目錄（預設是空的） | `/etc/woowtech-cockpit/backup/apps/` |
| 部署範本（只有安裝了需要的目錄項目時才有） | `/usr/local/share/woowtech-cockpit-backup/catalog/` |
| 排程備份的計時器與排程檢查（每 5 分鐘） | `/usr/local/lib/systemd/system/woowtech-cockpit-backup-schedule.timer`、`woowtech-cockpit-backup-schedule.service` |

安裝後頁面顯示「尚未設定可備份的應用」是正常的。每個應用都需要經審查的目錄項目才會出現，見 [app-catalog.md](backup/app-catalog.md)；**正式應用尚未啟用**。

- helper 只信任 root 擁有、群組與其他人不可寫入的程式與目錄。安裝器把這些資料夾設為 root 0755、檔案 0644（helper 0755）；若上層資料夾不是 root 擁有或可被群組／其他人寫入，安裝會拒絕並提示 `chmod go-w`，不做任何變更。
- 安裝器**從不**規劃、寫入、備份、驗證或回退執行資料：備份檔（`/var/lib/woowtech-backup/`）、加密金鑰（`/etc/woowtech-cockpit/backup/keys/`）與 `/run/woowtech-backup/`。這些由引擎在第一次使用時建立；重新安裝或回退介面不會刪除備份與金鑰。資料位置與清理見 [operations.md](operations.md)。
- 應用擁有者帳號需能執行 rootless Podman（subuid／subgid），並啟用 linger（`sudo loginctl enable-linger <應用擁有者>`），讓使用者服務管理器在沒有登入時也執行；否則頁面會提示「使用者服務管理器未啟動」。
- 安裝後第一次使用，請到「加密金鑰」建立金鑰並保存緊急金鑰，見 [backup.md](backup.md)。
- 「排程備份」預設關閉。安裝器一律安裝並啟用排程檢查的計時器（管理者用 `systemctl mask` 遮蔽它時除外，見下方）；排程關閉時它每 5 分鐘只做檢查，不會建立備份。開啟排程的方式見 [backup.md](backup.md)，維護見 [operations.md](operations.md)。
- `install` 會先檢查備份元件需要的工具是否真的能用（age、age-keygen、zstd、python3-nacl、python3-cryptography），缺的會用 apt 自動補裝（只裝這四個套件和它們的相依套件、不移除任何套件、不主動重新啟動服務），才開始更新檔案。補不了（例如這台連不到套件庫）時**更新照常進行**，安裝訊息（`notices`，也會印在畫面上）說明沒補到的套件、原因、補到之前不能用的功能，以及怎麼辦；排除後重新執行即可。`plan` 會先列出要補裝的套件（`packages`）；`sudo python3 scripts/manage.py status` 隨時可以查看（不會更動任何東西，缺套件時結束碼 1；用 `--no-backup` 留下的備份元件也會檢查）。`--no-backup` 與 `--root` 的安裝不檢查也不補裝套件，`--root` 會提示在該系統安裝。回退不會移除補裝的套件。

### 排程備份的系統單元

`woowtech-cockpit-backup-schedule.timer`（`OnCalendar=*:0/5`，沒有 `Persistent=`）啟動 `woowtech-cockpit-backup-schedule.service`（`Type=oneshot`，固定執行 `/usr/local/libexec/woowtech-cockpit-backup schedule-tick`，不讀任何輸入，helper 不存在時不執行；錯誤輸出（stderr，例如程式錯誤或無法啟動備份作業）以 warning 等級記入系統日誌）。兩者的名稱刻意不符合作業單元的 `woowtech-backup-*`。helper 從不寫入單元檔，也不執行 `daemon-reload`；單元檔只由安裝器管理：

- **只在實際系統（`/`）上**執行 `systemctl`，且只用固定參數、只指名這個計時器。安裝前把計時器原本的狀態（是否已啟用、是否在執行）記在安裝交易裡；寫入備份元件前若計時器在執行就先停止，寫完後若有單元檔變更就執行 `systemctl daemon-reload`，最後 `systemctl enable --now woowtech-cockpit-backup-schedule.timer`。沒有任何檔案需要更新時，若計時器被手動停用，安裝也會重新啟用它。安裝中途失敗時，檔案與計時器都恢復到安裝前的狀態。
- 計時器被管理者遮蔽（`systemctl mask`）時，安裝器把它當成管理者的決定：不啟用也不啟動它，安裝照常完成，輸出的 `notices` 說明排程備份因此不會開始；要恢復時先 `systemctl unmask woowtech-cockpit-backup-schedule.timer` 再重新安裝。其他 `systemctl` 失敗仍會讓安裝失敗並恢復原狀。
- **回退**只在那次安裝更動了備份元件（包含這兩個單元檔）時處理計時器：還原檔案期間先停止執行中的計時器（回退單元檔時也先停用它），還原或移除檔案，有單元檔變更時執行 `systemctl daemon-reload`。那次安裝曾停止計時器或更動了單元檔時，回退後計時器恢復到安裝前的狀態（安裝前已啟用或在執行就恢復原狀）；否則回退前在執行的計時器會再啟動。回退第一次加入排程備份的安裝，計時器就會停用並移除。沒有更動備份元件的安裝交易（例如 `--no-backup`），回退時完全不執行 `systemctl`。
- `verify` 會在輸出中列出計時器狀態（`timer`），但不算成差異（drift）；`plan` 會列出安裝將執行的 `systemctl` 步驟。
- `--no-backup` 不更動這兩個單元與計時器；`--root` 只寫入檔案、不執行 `systemctl`。在 `/` 上但系統不是由 systemd 啟動（沒有 `/run/systemd/system`，例如 chroot 或建置映像時）也一樣：只寫入檔案，並提示 systemd 執行後要執行的指令。
- 單元檔只以解析檢查（`scripts/check_source.py` 與單元測試）；**不要對實際系統或實驗室設備執行 `systemd-analyze verify`**（曾因 `--user` 驗證取代執行中管理程式的私有 socket，造成 Podman 健康檢查故障）。需要確認時用 `systemctl show woowtech-cockpit-backup-schedule.timer`。

**不要在備份、還原或驗證作業進行中安裝、更新或回退。** 安裝器不會自行檢查進行中的作業，替換或移除引擎與 helper 可能讓作業中途失敗。先到「備份與還原」的「活動紀錄」確認沒有「等待開始」或「執行中」的作業；也可在主機執行 `systemctl list-units 'woowtech-backup-*'`，沒有列出單元表示沒有作業在執行（排程檢查的計時器 `woowtech-cockpit-backup-schedule.*` 不在這個名稱範圍內）。開啟了排程備份時，避開排程時間前後安裝；安裝期間計時器會被暫停，但已開始的排程備份作業不會等安裝結束。

## 原生 Podman 版本閘

安裝器讀取 dpkg 的 cockpit-podman 版本，只對124版替換 `/usr/share/cockpit/podman/index.js` 或其 gzip 版本，並安裝相應授權。原檔納入安裝交易備份，支援 verify 與 rollback。125或其他版本不替換原生 JS，服務管理頁仍可使用。APT 升級可能覆寫 JS；升級後重新執行 plan／install／verify，並核對版本與瀏覽器行為。

`--no-services` 同時停止管理這份原生整合，但不移除已部署檔案；需要還原時使用相應交易 rollback。

## 反向代理

直接使用 9090 不需要本專案的代理設定。已有反向代理時，依 `examples/cockpit.conf.reverse-proxy` 填入自己的來源，合併到現有 `/etc/cockpit/cockpit.conf`，不要直接覆蓋整份檔案。代理須支援 WebSocket 並正確傳遞協定標頭。未在本次測試新的代理環境。

官方參考：[Ubuntu 安裝](https://cockpit-project.org/running.html)、[Cockpit 設定](https://cockpit-project.org/guide/latest/cockpit.conf.5.html)。
