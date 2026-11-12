# 維護與回退

## 更新來源

```bash
git pull --ff-only origin main
sudo python3 scripts/manage.py plan
sudo python3 scripts/manage.py install
sudo python3 scripts/manage.py verify
git rev-parse HEAD
dpkg-query -W cockpit-bridge cockpit-podman
```

出貨時記錄 commit、`VERSION`、實際套件版本及安裝輸出的 `backup_id`。安裝腳本沒有背景更新工作。要固定來源可先 `git checkout <已驗證的 commit>` 再執行安裝。

驗證會比對已管理檔案的 SHA-256。若顯示 `drift`，先查看是上游升級或人工修改，再決定重新安裝。它只檢查檔案內容，不是服務健康、權限或完整安全稽核。

## 回退一次介面安裝

```bash
sudo python3 scripts/manage.py rollback <安裝輸出的 backup_id>
```

程式先檢查所有現有檔案與備份雜湊，再還原該次交易的原檔與權限；只刪除該交易新增的檔案，不遞迴刪除整個目錄。備份保留供追查。若檔案已被後續安裝、APT 升級或人工修改，回退會拒絕覆蓋。多次安裝應由最近一次向前回退。

安裝中捕捉到的寫入失敗會立即還原已寫入檔案；遇斷電等未能捕捉的中斷，可使用狀態為 `prepared` 的交易回退。磁碟故障仍可能使恢復失敗，需要依設備復原流程處理。

**這是品牌檔案回退，不是應用、資料庫、整機或客戶備份檔的還原。** 不安裝／解除安裝 APT 套件、不還原 Cockpit 密碼、TLS 或防火牆。第一次安裝回退後沒有狀態檔是正常的；若回退到先前來源版本，verify 會檢查先前版本。

## 常見問題

| 現象 | 檢查方式 |
| --- | --- |
| 新頁或新增圖片 404 | 登出再登入，重新建立 Cockpit bridge 的套件檔案清單；再強制重新整理 |
| 顏色仍是舊版 | 瀏覽器可能快取 static/branding.css；重新整理、確認 verify 與實際載入的 CSS |
| 只有某個頁面未套用品牌 | 檢查原生 HTML 是否被 APT 覆寫，重跑 plan／install；檢查新版類別 |
| Podman 顯示零容器 | 確認登入者、管理權限、擁有者選單及對應 rootless 儲存區 |
| 圖集顯示待擷取 | 正常：新設備未匯入截圖；依 testing.md 擷取再匯入 |
| 手機圖截斷 | 使用 capture 的完整總覽輸出，不用固定高度截取 iframe；圖集可捲動原圖 |
| 更新頁一直載入 | 檢查 PackageKit/APT；此品牌來源沒有解決後端套件來源問題 |
| 缺歷史指標 | 另外配置 PCP／cockpit-pcp；這次沒有將其納入 bootstrap |
| 開不了 9090 | 檢查 cockpit.socket、路由、防火牆及 TLS；品牌檔案不控制連接埠 |

不要為了讓圖集出現而重新啟動所有容器；圖集只是 Cockpit 套件。此安裝器不主動中斷 Cockpit 或既有應用服務。
