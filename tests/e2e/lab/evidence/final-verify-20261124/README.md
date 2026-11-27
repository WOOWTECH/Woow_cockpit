# 最終整合版本實測（2026-11-24，final-verify）

擁有者的要求：「用最終版本把每個服務再實測一輪」。這個資料夾記錄每個服務用最終整合版本、真實 HA 備份、
在實驗室設備上跑完一輪的結果。所有實驗室設備都沒有網路（network=none）、沒有對外連接埠；正式環境沒有被動到。

`commercial_acceptance`：**not-complete**（理由見最後一節）。

## 用的是哪個版本

- 最終版本（FINAL-2）：`ccc3ed75da74261b52837beaeba46b29b2bb115e`（integration-3 的 `INTEGRATION FINAL-2` 那一行）。
- EMQX 在最終版本上實測（worktree `/tmp/final-verify-ccc3ed7`，乾淨、detached）。
- 其他應用在整合版 `4353892`（arm54-2 squash）上實測（Headscale 從 `70bcf6f`、Odoo ARM 擷取與重跑從 `0718f77`：都只多了測試程式的修正，引擎相同）；主程序 17:56 同意先跑，條件是最終版本的
  `backup-engine/` 與 `backup/`（頁面）和 `4353892` 相比，只能差在 EMQX 匯入程式。實際差異（`git diff --stat 4353892 ccc3ed7 -- backup-engine backup`）：

```
 backup-engine/woowbackup/ha_emqx.py  | 355 ++++++++++++++++++++++++++++++++---
 backup-engine/woowbackup/hacommon.py |  25 ++-
 2 files changed, 354 insertions(+), 26 deletions(-)
```

- `ha_emqx.py`：只有 EMQX 匯入用到，EMQX 已在最終版本上重新實測。
- `hacommon.py`（如有差異）：只有 `names()`（加上它用的 `clean()` 與 `HIDDEN_CATEGORIES`）：顯示的名稱把 Unicode Cc/Cf/Cs/Cn/Zl/Zp 字元換成 `?`。呼叫它的匯入程式（codeserver、emqx、headscale、hermes、litellm、nextcloud、omnigent、opendesign）都只拿它組顯示文字（阻擋、警告、提醒與錯誤訊息、Omnigent 報告的 alembic 欄位），沒有任何檔名、路徑、比較或儲存值用到它；patch-id `0c9112aa99bd`＝emqx-secreview 第 8 輪的那個改動。所以 `4353892` 上非 EMQX 的實測結果在最終版本上仍成立。

## 結果總表

| 應用 | 設備 | 結果 | 通過／失敗 | 秒數 | 來源 commit | 證據 |
| --- | --- | --- | --- | --- | --- | --- |
| Hermes | dev-d | PASS | 90／0 | 359.9 | `4353892e` | `hermes-real-20261123/attempt-13-final-verify-x86-enc-cleanup-leaks.json` |
| Headscale (attempt, kept) | dev-d | FAIL | 99／2 | 544.8 | `4353892e` | `services-a-real-20261123/headscale-fullflow-arm-attempt2-final-verify.json` |
| Headscale | dev-d | PASS | 101／0 | 301.9 | `70bcf6ff` | `services-a-real-20261123/headscale-fullflow-arm-attempt2-final-verify-r2.json` |
| Omnigent | dev-d | PASS | 112／0 | 486.5 | `4353892e` | `omnigent-product-20261123/omnigent-x86-enc-attempt4-final-verify.json` |
| LiteLLM | dev-d | PASS | 80／0 | 1522.6 | `4353892e` | `litellm-product-20261123/attempt-11-final-verify.json` |
| EMQX import (pre-final a1b690f) | dev-d | PASS | 101／0 | 1024.5 | `a1b690f4` | `emqx-product-20261123/attempt-final-verify-01.json` |
| EMQX rollback/cleanup (pre-final a1b690f) | dev-d | PASS | 101／0 | 472.3 | `a1b690f4` | `emqx-product-20261123/attempt-final-verify-02.json` |
| EMQX import (FINAL-2) | dev-d | PASS | 101／0 | 756.0 | `ccc3ed75` | `emqx-product-20261123/attempt-final-verify-01-r2.json` |
| EMQX rollback/cleanup (FINAL-2) | dev-d | PASS | 101／0 | 375.0 | `ccc3ed75` | `emqx-product-20261123/attempt-final-verify-02-r2.json` |
| Odoo/n8n ARM full (attempt 1, kept) | dev-c | FAIL | 126／4 | 2446 | `4353892e` | `odoo-n8n-final-20261123/final-verify-20261124-arm-full.json` |
| Odoo ARM source capture (new, mail rows) | dev-c | PASS | acceptance true（explained_row_differences） | 254 | `0718f774` | `odoo-n8n-final-20261123/final-verify-20261124-capture-arm.json` |
| Odoo/n8n ARM full (rerun) | dev-c | PASS | 133／0 | 2164 | `0718f774` | `odoo-n8n-final-20261123/final-verify-20261124-arm-full-r2.json` |
| Odoo/n8n x86 full | dev-c | PASS | 94／0 | 1251 | `4353892e` | `odoo-n8n-final-20261123/final-verify-20261124-x86-full.json` |
| Odoo/n8n x86 fix | dev-c | PASS | 40／0 | 474 | `4353892e` | `odoo-n8n-final-20261123/final-verify-20261124-x86-fix.json` |
| Nextcloud (share) | dev-e | 未執行 | – | – | – | – |
| OpenDesign | dev-e | 未執行 | – | – | – | – |
| code-server | dev-e | 未執行 | – | – | – | – |

狀態（2026-11-24 23:5x 寫入，之後會更新）：dev-e 的 Nextcloud 分享實測正在跑（主機磁碟夠了：dev-c 的 Odoo 映像輪替後
21.65 GB）；code-server 和 OpenDesign 要等更多主機磁碟空間（分別要 26.5 GB、28.7 GB，靠 Nextcloud 輪替與 dev-c 第二次輪替）。
表裡「未執行」的列就是還沒跑的項目。

說明：「通過／失敗」是測試程式自己的總數（`RESULT n/m` 或 `<flow>: n/m PASS`）。每一列的證據 JSON 只放結束碼、
固定的狀態行、秒數、stdout 的 sha256 與來源 commit；完整輸出放在主機私有資料夾（0600），不提交。

## SR-5「雜湊方式相同時不改變」路徑（只記數量）

真實 RPi5 ARM 冷備份（EMQX 停止時製作）的檢查回覆，由產品自己的檢查流程產生、測試程式存檔，再由
`sr5_counts.py` 只數數量（不印任何帳號名稱、值或文字）：

- 檢查回覆檔的 sha256：`7a0f45ee305c23d77650fd72592c6fdff42496806599767ebdf2ea96ba94d64a`（主機私有資料夾，0600，不提交）
- ok：true；阻擋 0 項；警告 2 項（只數數量；emqx-secreview 在同一批真實備份上看到的是兩個一般警告：沒有規則對應的主題、API 金鑰改用這台設備的）；HA 內建 MQTT 使用者 3 個；工作檔 6 個。
- 密碼儲存相關文字（SR-5 ACCOUNTS_STOP、PLAIN_REFUSED、SR-11 PLAIN_ELSEWHERE、CLEAR_ROWS、DB_OFF、HASH_UNREADABLE）在阻擋、警告與工作檔裡的總數：0（18 個計數全部為 0）。和 emqx-secreview 第 8 輪的預測相同：HA 與這台設備都用 sha256 加 suffix 時，什麼都不改。

## 失敗的嘗試與修正（全部保留）

- Headscale 第 1 次（`3d45b63`，99/101，保留）：實驗室前置條件（`headscale-entrance` 沒有在跑），不是產品問題。
  測試程式改成三個 unit 都重新啟動（`70bcf6f`），重跑 101/101（`8a3dd60`）。
- Odoo/n8n ARM 全套第 1 次（`9a910db`，126/130，保留）：
  - 3 項 armcompare 失敗＝測試工具的輸入加上日期：11-23 的 ARM 來源擷取還沒有逐列記錄 `mail_mail`、`mail_message`，
    而今天剛好是 RPi5 備份（11-19）後第 5 天，Odoo 的註冊提醒排程（auth_signup `res_users.py:248-276`）寄出 1 封提醒信。
    修正：測試程式 `0718f77`（擷取時從既有的 creds 檔讀實驗室金鑰，不寫新檔），重新擷取（`3f12030`：來源＝RPi5 指紋
    205/205，提醒信逐列解釋），再重跑 ARM 全套：**133/133 通過**（`1c1a274`，2166 秒）：3 項 armcompare 全部通過（37 個逐列差異都對上原廠規則，包括那封提醒信），db2 這次也通過（49 秒）。
  - 1 項第二個資料庫（woowtest2）轉換失敗＝**產品穩定性問題**：主機負載約 21 時，寫入 pg_restore 清單的
    `podman exec` 輸入資料遺失（`ha_odoo.py` `Cluster.write_file` 沒有讀回核對），之後的 SQL 才失敗。失敗時沒有留下
    錯誤資料（fails closed），但錯誤訊息會誤導。同一步驟在 x86 全套和 11-23 都通過。修正由 pg-stdin-fix lane 處理，
    擁有者決定放進這個 PR 或下一個 PR。
- dev-c 啟動的前三次（18:53、19:03 等，沒有證據檔）：我的啟動腳本與實驗室時序問題（等使用者服務管理器、映像），已修好。
- EMQX 在 `a1b690f` 的兩次（`69432f0`、`bd767db`，都通過）是最終版之前的版本，已由最終版 `ccc3ed7` 的兩次取代。

## 模擬了什麼（每個測試程式的說明與證據裡都有寫）

- 全部應用：沒有操作瀏覽器頁面本身（dev-c、dev-d、dev-e 都沒有對外連接埠）。測試程式送的是頁面會送的同一個
  root helper 指令（一個 JSON 請求、一個 JSON 回覆），引擎是這次部署進去的那一份（每次都核對已安裝引擎＝測試樹）。
- Headscale：實測期間把 DERP 區塊換成內嵌的 region 999（結束時寫回）；客戶端是 dev-d 私有網路命名空間裡的
  userspace tailscaled，用的是 RPi5 上做出來的客戶端身分（不是 RPi5 本身）；重新連線沒有用新金鑰。
- LiteLLM：實驗室衍生映像（USER 1000:0）；沒有呼叫任何模型供應商、沒有更新 ChatGPT token（dev-d 沒有網路）。
- Hermes：dev-d 用 `--no-llm` 跑 Hermes，沒有和模型對話；HA 的 mock 模型回覆只當資料核對。
- EMQX：HA 內建資料庫來源依擁有者給客戶的說明，用 REST API 加入；第一次匯入中的兩次失敗（啟動失敗、讀回竄改）
  是測試程式刻意注入的，兩次都自動回復。
- Odoo/n8n x86 失敗情境：空間不足＝在 staging 上掛一個限制大小的 tmpfs；回復＝注入 odoo-db 第一次啟動失敗；
  中止與取消由測試程式送出。`pull` 情境沒跑（需要 Docker Hub 網路）。
- Odoo ARM 來源擷取：引擎工作在 dev-c 裡直接執行（同一份已安裝的引擎，經轉換掛鉤記錄），只做 Odoo，不經頁面。
  它只提供 ARM 逐列比對的來源資料，驗收靠 ARM 全套。

## 沒有涵蓋的

- 瀏覽器頁面本身、主機或設備重開機。
- 實驗室以外的裝置：EMQX 的外部 MQTT 裝置、Headscale 另一台機器上的客戶端、HA 的第二個節點、Headplane 介面。
- 需要網路的部分：模型供應商呼叫、ChatGPT token 更新、Odoo `pull` 情境、真的寄出郵件。
- Hermes 的 ARM 版本（Hermes add-on 只有 amd64）。
- Hermes 的獨立 FTS／SQLite 安全審查：仍是人工項目（自動審查被拒，不經其他途徑重試）。
- Pi agent 與 Omnigent 的模型設定（不在範圍內）。
- 正式環境：完全沒有碰。
- 實體 ARM 目標機 .54 的實測由 arm54 lane 負責，不在這一輪。

## 為什麼 commercial_acceptance 仍是 not-complete

- 這一輪全是實驗室實測（network=none 的 dev-c／dev-d／dev-e）。商業驗收要擁有者在真實客戶環境走完整個流程，
  實驗室結果不能代替。
- Hermes 的獨立安全審查仍待人工完成。
- Odoo 第二個資料庫轉換在主機高負載時失敗過一次（產品穩定性問題，修正由 pg-stdin-fix lane 處理）。
- 上表裡標「未執行」或「FAIL」的項目（如果有）見「失敗的嘗試與修正」與「沒有涵蓋的」。
