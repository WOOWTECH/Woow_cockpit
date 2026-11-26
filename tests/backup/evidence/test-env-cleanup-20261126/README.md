# 測試環境清理（2026-11-26）

Owner 已明確授權：這台服務目前都只是測試，可清掉不需要的映像與快取。這一輪保留原始 HA 備份、安全備份、資料卷、目前容器、既有服務單元引用的映像、現行實測腳本需要的映像與最新 RC23 候選版本。

## 已執行

- 執行 `pnpm store prune`，結束碼 0。
- 移除 2 個未使用的 npx 快取目錄；逐一檢查程序參照後，保留 3 個仍在使用的 MCP 快取。檢查只記錄 PID 與程序名稱，不保存命令列或環境中的憑證。
- 移除已無建置／匯入程序使用的 `/var/tmp/container_images_oci1032315544` 與 `/var/tmp/buildah-cache-1000`。
- 清理超過 24 小時的未標籤映像。
- 移除 55 個已被新版取代的舊測試映像標籤：舊 Hermes、code-server、Nextcloud 與 MCP 映像；超過 7 天且無容器／服務／實測腳本引用的本地測試映像；已有 RC23 時不再使用的 RC14–RC22。逐個移除前重新確認沒有建置程序及新容器引用，不使用強制刪除映像或刪除資料卷的選項。

三個清理階段前後，容器與資料卷清單完全一致。可用空間由 **28,354,396,160 bytes（26.41 GiB）** 到 **34,652,192,768 bytes（32.27 GiB）**，淨增加約 **5.87 GiB**；同時有其他寫入者，這是檔案系統實際差值。先前 Podman 的 33.3 GiB 是包含共用層的估算，不能把每個標籤的完整大小直接相加。

`summary.json` 記錄總結；`result.json`、`old-test-images-result.json` 與 `superseded-test-images-result.json` 記錄各階段選取、移除與保留結果。原始盤點、指令輸出留在私人目錄 `~/.woowbk-lab/evidence/test-env-cleanup-20261126/`。

## 系統日誌：等待 root 執行

目前 `sudo -n` 要求密碼，因此尚未修改 `/var/log`。Owner 已收到可檢查的指令：

```sh
sudo bash /tmp/parity-system-log-cleanup-20261126.sh --apply
```

本目錄的 `cleanup-system-logs.sh` 是同一份腳本，已通過 `bash -n`。它確認 `syslog.1` 無開啟者，壓縮後完整解壓比對並確認來源未變，才移除原始的輪替檔；封存 journal 按 7 天／1 GiB 上限清理。現用 syslog 不會被截短或刪除。執行後仍須回收實際結果，不能提前宣稱這部分已完成。
