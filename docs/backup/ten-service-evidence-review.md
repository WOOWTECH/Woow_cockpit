# 十服務證據總核對（HA 匯入）

核對日：2026-11-28。對象：main `35f42249` 裡**已提交**的證據（`docs/backup/`、`tests/backup/evidence/`、`tests/e2e/lab/evidence/`、`snippets/`、`tests/backup/ha_parity_rows.json`）。這次只讀檔案與 git 紀錄，沒有連任何設備，也沒有讀私人證據的內容。`commercial_acceptance` 仍是 `not-complete`。

## 結論

- **十個服務都有實機證據，而且都已在真的 Cockpit 頁面上匯入成功。** 狀態文件（[final-acceptance-status.md](final-acceptance-status.md)）寫的數字，絕大多數和證據檔一致；引用的 commit 都存在。
- **找到兩處寫錯，已改正**：
  1. Headscale 真畫面是 **123／123**，不是 125／125。驅動程式自己的總數行寫 `123/123 PASS`；125 多算了兩行外層前置檢查（「source tree committed」「mutation lock acquired」），同一支程式的 96／96 也沒有算這兩行。
  2. R9 那一行說 PR #23 還是草稿、等擁有者推送與合併；git 裡 PR #23 已在 2026-11-28 04:51 合併（`ee520d49`，含 CI 修正 `f341143e` 與 Nextcloud 重測 `4cf97c25`），之後 #24（`ddcdba87`）、#25（`35f42249`）也已合併。
- 各服務一句話：

| 服務 | 判斷 |
|---|---|
| Nextcloud | 最完整：完整 share 的頁面跑法涵蓋輔助程式的全部情境；略過項目與伺服器端加密（S5）只走輔助程式 |
| OpenDesign、Headscale、code-server | 頁面跑法涵蓋輔助程式的完整流程（code-server 的 D10 只走輔助程式）；缺的是範圍外的項目（提供者登入、配對、重開機）；Headscale 只測過未加密的 HA 備份 |
| LiteLLM | 頁面跑法幾乎涵蓋全部；「轉換後才寫入的其他資料庫」只在輔助程式證明 |
| n8n | 完整執行個體流程（輔助程式）證明充分；頁面只跑應用流程 |
| EMQX | 頁面、套件升級、R4 全部情境都通過；頁面沒有重新啟動與故意失敗，故意失敗的自動回復只在 11-26 較舊的 EMQX 程式上做過，而且只有說明文字 |
| Omnigent | 輔助程式（一次性目標）完整；頁面只證明匯入與還原原狀 |
| Hermes | 匯入、重新啟動、用匯入前備份退回都證明；**從來沒有做過「故意失敗→自動回復」** |
| Odoo | 只在替代映像上證明（不是原始租戶驗收）；沒有重新啟動，也沒有故意失敗 |

- ARM 主機上的驗收：擁有者 2026-11-28 決定本輪略過。

## 怎麼核對的

- 每一個數字都打開證據檔：數 `: PASS` 行，並和驅動程式自己的總數行（例如 `code-server full flow: 105/105 PASS`）對照；JSON 紀錄則數 `ok: true`。
- 每一個 commit 用 `git cat-file -e <hash>^{commit}` 確認存在、用 `git merge-base --is-ancestor` 確認在不在 main；不在 main 的，用 `git patch-id` 找 main 裡內容相同的那一個。
- 用詞：「**輔助程式**」＝測試程式直接呼叫頁面會送的那些備份元件指令；「**真畫面**」＝真的 Cockpit 362 頁面（無頭 Chromium，經私有轉送進入沒有網路的實驗室設備）。「**產生的來源**」＝測試自己做出的資料，不是原始 HA 備份。「**只有說明**」＝數字只寫在 README，原始紀錄在主機私人資料夾，沒有提交。
- 範圍：逐檔核對的是 2026-11-25 HAOS 對齊之後（目前產品行為）的實機結果。更早的世代（11-20～24）產品行為已改（例如原本拒絕的情形改成確認行），只列在附錄。

## 共通驗收項目（從 repo 的文件定出，沒有另加要求）

repo 裡沒有 DESIGN 文件本身，但測試與證據引用了它的 G1（一條確認行的三步）、G4（R1～R9 實機項目，R8＝真畫面、R9＝整合、畫面、版本差異與十服務證據核對）、G5（失敗紀錄保留）。下表的每一項都來自 repo 裡的文字：

| 代號 | 項目 | 白話 | repo 依據 |
|---|---|---|---|
| C1 | 檢查 | 檢查不停應用、不改資料 | [backup.md](../backup.md)「從 Home Assistant 備份匯入」步驟 6 |
| C2 | 未確認就拒絕 | 有要確認的事項時，沒勾就不能轉換 | 步驟 7「沒有勾就不能按「匯入」」；DESIGN G1（[test_ha_parity_rows.py](../../tests/backup/test_ha_parity_rows.py) 說明） |
| C3 | 真實匯入 | 轉換＋還原，還原前自動做匯入前備份 | 步驟 8 |
| C4 | 匯入後驗證 | 應用真的能用，不只是容器在跑 | [execution-handoff.md](execution-handoff.md)「驗收與交付檢核」 |
| C5 | 重新啟動後驗證 | 重新啟動後資料仍在、仍能用 | [LiteLLM 流程的必要檢查點](../../snippets/focus-litellm-instance-acceptance/README.md)；狀態文件各列 |
| C6 | 故意失敗→自動回復 | 還原失敗時自動退回 | 步驟 8「失敗會自動退回」；[CONTRACT.md](CONTRACT.md) §13 F8 |
| C7 | 手動回復 | 用匯入時自動做的「匯入前備份」還原回去 | 步驟 9「要退回就用它還原」 |
| C8 | 原狀精確回復 | 測完設備和測之前一模一樣 | LiteLLM 必要檢查點；狀態文件「精確回到原狀」 |
| C9 | 只清自己的 | 只刪這次測試建立的東西 | LiteLLM 必要檢查點；狀態文件 R8 一段 |
| C10 | 機密掃描 | 金鑰、密碼、登入值沒有留在紀錄或日誌 | execution-handoff「測權限與敏感資訊洩漏」；CONTRACT §10 |
| C11 | 真畫面 | 用真的 Cockpit 頁面做 | DESIGN G4 R8（[parity-page-20261125](../../tests/backup/evidence/parity-page-20261125/README.md)） |
| C12 | 加密的 HA 備份 | 要輸入 HA 備份金鑰的備份 | 步驟 1、5 |
| C13 | 未加密的 HA 備份 | 不問金鑰的備份 | 步驟 3、5 |
| C14 | 版本不同 | HA 與這台的版本不同時照規則提醒或擋下 | backup.md「條件」；狀態文件 R9「版本差異」 |
| C15 | ARM | ARM 主機上的驗收 | backup.md「條件」（x86 與 ARM 的備份都能匯入）；狀態文件 ARM 一段 |

## 各服務的實機結果

設備：dev-c、dev-d、dev-e 都是沒有網路、沒有對外連接埠的實驗室容器。commit 欄「驅動／產品」：同一個值表示測試程式裝的就是自己那份原始碼。表中不在 main 的 commit，main 裡都有內容相同（`git patch-id` 相同）的提交：`ce8c4cfb`＝`aaadebc9`、`bfe7b914`＝`7115bbaa`、`550478ae`＝`1817feec`、`687cc9b7`＝`18f60897`、`5209c402`＝`7f0b8b27`、`a82a086f`＝`c0fff26e`、`27cb52c4`＝`abc74683`、`516e02a2`＝`6b48e1ca`、`95617696`＝`d927201d`。

### EMQX

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| EM1 | 未損壞的原始 B1（加密）只匯入 EMQX，列出的確認行確認一次 | 81／81 | 11-28 | dev-d | `e236d5d6`／`ce8c4cfb` | 真畫面 | [capture](../../tests/backup/evidence/focus-acceptance-20261127/page-emqx-20261128-capture.json)、[summary](../../tests/backup/evidence/focus-acceptance-20261127/page-emqx-20261128-summary.json) |
| EM2 | 在 5.8.9 匯入真實 x86 冷備份，換 5.8.8 後用套件 upgrade.sh 升回 5.8.9 | 61／61 | 11-28 | dev-d | `e8efa58e`／證據未記錄 | 輔助程式 | [upgrade-capture.json](../../tests/backup/evidence/parity-emqx-upgrade-20261128/upgrade-capture.json) |
| EM3 | R4 產生情境 11 個：明文 23、失效帳號 23、匿名 24、預設管理員 24、ACL 31、PSK 26、HTTP 驗證 29、檔案機密 27、jq 27、環境變數 27、遺失驗證設定依預期拒絕 15；H1 28 | 全部通過 | 11-27～28 | dev-d | `27cb52c4`、`42d9f5ed`、`c1f03cf0`、`cf05b399` | 產生的來源 | [focus-emqx-r4-20261127](../../tests/backup/evidence/focus-emqx-r4-20261127/generated-20261128-README.md) |
| EM4 | E-44 外掛紀錄清理 | 33／33 | 11-27 | dev-d | `a82a086f` | 產生的來源 | [runtime-attempt3-pass.json](../../tests/backup/evidence/parity-emqx-plugins-focus-20261127/runtime-attempt3-pass.json) |
| EM5 | R4 D0：原始 B1 檢查（ARM＋x86）、x86 匯入、故意失敗回復＋E-90、清理 | 31／31、56／56、76／76、11／11 | 11-26 | dev-d | 產品 `d0cfef06` | 輔助程式 | [README](../../tests/backup/evidence/parity-emqx-r4-d0-20261126/README.md)（只有說明） |

另見跨服務的 R1、R8（EMQX 損壞時只排除它）。狀態文件 EMQX 列與證據一致；「既有完整檢查／匯入／回復」指的是 EM5。

### Odoo（全部用替代映像）

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| OD1 | 冷叢集保留：上傳、從檢查提供的兩個資料庫選 woowtest2、兩條確認行確認一次、保留副本與放回 | 80／80 | 11-28 | dev-c | `f4c41494`／`bfe7b914` | 真畫面 | [page-cold-keep.json](../../tests/backup/evidence/parity-odoo-page-20261128/page-cold-keep.json) |
| OD2 | 冷叢集保留 | 37／37 | 11-26 | dev-c | `80fb6dcf` | 輔助程式 | [README](../../tests/backup/evidence/parity-odoo-cold-keep-20261126/README.md)（只有說明） |
| OD3 | 離線 PostgreSQL 16 產物（amd64）安裝、載入、重用（映像，不是匯入流程） | passed | 11-27 | dev-d | `516e02a2` | 輔助程式 | [od23-r5-result.json](../../tests/backup/evidence/parity-odoo-pg16-offline-20261127/woowbk-odoo-pg16-proof-20261127-od23-r5-result.json) |

### n8n

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| N1 | 原始 n8n 完整執行個體流程 | 85／85 | 11-27 | dev-c | `5baafcb2`／`bfe7b914` | 輔助程式 | [attempt7.json](../../tests/backup/evidence/focus-instances-20261127/n8n-instance-flow-attempt7.json) |
| N2 | 原始應用流程，上傳、檢查、確認、匯入改走頁面 | 61／61 | 11-28 | dev-c | `d500e379`／`bfe7b914` | 真畫面 | [n8n-x86-…json](../../tests/backup/evidence/focus-acceptance-20261127/n8n-x86-20261128T091424-3862de6b.json) |
| N3 | 原始應用流程 | 34／34 | 11-26 | dev-c | — | 輔助程式 | 只有參照：[old-safety-provenance.json](../../snippets/focus-n8n-instance-acceptance/old-safety-provenance.json) 記私人路徑與雜湊 |
| N4 | 產生的 PostgreSQL 執行個體（n8n 與 LiteLLM） | 87／87 | 11-27 | dev-c | `95617696` | 產生的資料庫 | [generated-pg-c-04.json](../../tests/backup/evidence/focus-instances-20261127/generated-pg-c-04.json) |

N1 的提交紀錄只看得到 84 個檢查名稱。第 85 個 `mismatch_refused_by_the_compatibility_check_without_change`（不一致的備份在任務內被拒）有 58 個字元，紀錄程式 [services_a_capture.py](../../tests/e2e/lab/services_a_capture.py) 只保留 40 個字元以內的名稱，所以被丟掉。驅動程式自己的總數是 85、`runtime_acceptance: true`、結束碼 0，而它的 `require()` 一失敗就中止，所以這一項是通過的，只是紀錄裡看不到名字。

### Nextcloud

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| NC1 | 完整 share（4.47 GB 原始加密備份） | 118／118 | 11-27 | dev-e | `550478ae`／`5168f1ec` | 輔助程式 | [fullshare05-checks.txt](../../tests/backup/evidence/focus-nextcloud-r6-20261127/fullshare05-checks.txt)、[RESULT](../../snippets/focus-nextcloud-r6/fullshare05-RESULT.md) |
| NC2 | 完整 share 走頁面 | 145／145 | 11-28 | dev-e | `22fd2cb4`（產品＝同一份） | 真畫面 | [page-fullshare-case.json](../../tests/backup/evidence/parity-nextcloud-fullshare-page-20261128/page-fullshare-case.json) |
| NC3 | 沒有 share 資料夾，走頁面 | 82／82 | 11-28 | dev-e | `687cc9b7`（產品程式同 `b058df27`） | 真畫面 | [page-noshare-case.json](../../tests/backup/evidence/parity-nextcloud-page-20261128/page-noshare-case.json) |
| NC4 | 略過項目：衍生備份多一個符號連結與巢狀 .htaccess | 140／140 | 11-28 | dev-e | `3b4d8823`／`b058df27` | 輔助程式 | [skipped-entries checks](../../tests/backup/evidence/focus-nextcloud-r6-20261127/skipped-entries-20261128-checks.json) |
| NC5 | 伺服器端加密 S5（產生的來源，HA 格式未加密） | 96／96 | 11-28 | dev-e | `3f284a39`／`b058df27` | 輔助程式 | [s5b result](../../tests/backup/evidence/focus-nextcloud-r6-20261127/s5b-import-acceptance-20261128-result.json) |
| NC6 | 較早的完整 share | 113／113 | 11-24 | dev-e | `6a67eefa` | 輔助程式 | [share-attempt7.json](../../tests/e2e/lab/evidence/nextcloud-import-20261123/nextcloud-x86-share-attempt7.json) |
| NC7 | 沒有 share 資料夾 | 36／36 | 11-26 | dev-e | `a3f49012` | 輔助程式 | 只有參照：[readonly-inventory.json](../../tests/backup/evidence/focus-nextcloud-r6-20261127/readonly-inventory.json) |

### Omnigent

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| OM1 | 原始 x86 B1 加入無作用的額外資料庫物件（構造來源），裝在一次性目標上 | PASS（22 個固定事件） | 11-26 | dev-d | `3dad5e06` | 輔助程式 | [full-flow-extra-objects-x86.json](../../tests/backup/evidence/parity-omnigent-r7-20261126/full-flow-extra-objects-x86.json) |
| OM2 | 原始 x86 B1，一次性目標 | PASS | 11-26 | dev-d | `67ff6a04` | 輔助程式 | [README](../../tests/backup/evidence/parity-omnigent-r7-20261126/README.md)（只有說明） |
| OM3 | R8 第五次：選三個（損壞 EMQX 被排除），Omnigent＋Hermes 一次確認匯入 | 85／85 | 11-27 | dev-d | `0118d53d`／`59a1b0f9` | 真畫面 | [r8-page5-capture.json](../../tests/backup/evidence/focus-acceptance-20261127/r8-page5-capture.json) |
| OM4 | R1：同樣三選走輔助程式 | 70／70 | 11-28 | dev-d | `2d8fe242`／`ce8c4cfb` | 輔助程式 | [r1-helper checks](../../tests/backup/evidence/focus-acceptance-20261127/r1-helper-20261128-checks.txt) |

### LiteLLM

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| LL1 | 原始 LiteLLM 完整執行個體（案例 b11，這台 PostgreSQL 17） | 68／68 | 11-27 | dev-d | `0e1704e1`／`ce8c4cfb` | 輔助程式 | [fullflow-07.json](../../tests/backup/evidence/focus-instances-20261127/litellm-instance-fullflow-07.json) |
| LL2 | 同一流程走頁面（案例 b12），事後與基準 0 差異 | 92／92 | 11-28 | dev-d | `afbb90b6`／`ce8c4cfb` | 真畫面 | [flow-output.json](../../tests/backup/evidence/parity-litellm-page-20261128/flow-output.json)、[differences-after-run.json](../../tests/backup/evidence/parity-litellm-page-20261128/differences-after-run.json) |
| LL3 | 較早的原始應用流程 | 80／80 | 11-24 | dev-d | `4353892e` | 輔助程式 | [attempt-11-final-verify.json](../../tests/e2e/lab/evidence/litellm-product-20261123/attempt-11-final-verify.json) |

狀態文件說「匯入後 11 項及重新啟動後 12 項」：提交的紀錄只有 `saved80_verify`、`saved80_step_restart` 各一行通過，看不到 11 與 12 這兩個數字。

### Hermes

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| HE1 | 原始加密 x86 備份，目標改成完整執行個體並多一個資料庫與角色 | 105／105 | 11-27 | dev-d | `0d04a097` | 輔助程式 | [complete-flow.json](../../tests/backup/evidence/parity-hermes-instance-20261127/complete-flow.json) |
| HE2 | R8 第五次（同 OM3） | 85／85 | 11-27 | dev-d | `0118d53d`／`59a1b0f9` | 真畫面 | 同 OM3 |
| HE3 | R1（同 OM4） | 70／70 | 11-28 | dev-d | `2d8fe242`／`ce8c4cfb` | 輔助程式 | 同 OM4 |

### Headscale

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| HS1 | 未加密的 b1 備份第一次走頁面（不問金鑰），真的 Tailscale 客戶端 | **123／123** | 11-28 | dev-d | `d500e379`（產品程式同 `b058df27`） | 真畫面 | [page-full-flow.json](../../tests/backup/evidence/parity-headscale-page-20261128/page-full-flow.json) |
| HS2 | 原始未加密 x86 完整流程（HS-15 之後） | 96／96 | 11-27 | dev-d | `6ccf7106` | 輔助程式 | [original-ha-x86-full-flow.json](../../tests/backup/evidence/parity-headscale-virtual-20261127/original-ha-x86-full-flow.json) |
| HS3 | 額外虛擬資料表：沙盒子程序（產生的資料庫） | 通過 | 11-27 | dev-d | `6ccf7106` | 產生的來源 | [installed-child-generated.json](../../tests/backup/evidence/parity-headscale-virtual-20261127/installed-child-generated.json) |

HS1 的證據 README 原本也寫 125／125，已同步改成驅動程式自己的 123／123（2026-11-28）；狀態文件也已改正。

### OpenDesign

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| ODE1 | 原始加密 x86 展示備份走頁面；之後唯讀基準檢查 7／7 | 103／103 | 11-28 | dev-e | `c16651a8` | 真畫面 | [page-full-flow.json](../../tests/backup/evidence/parity-opendesign-page-20261128/page-full-flow.json)（7／7 只有說明） |
| ODE2 | 在 PR #23 引擎上重跑；基準 7／7 | 85／85 | 11-27 | dev-e | `4cf97c25` | 輔助程式 | [parity-opendesign-r9-20261127](../../tests/backup/evidence/parity-opendesign-r9-20261127/current-full-flow.json) |
| ODE3 | R8；基準 7／7 | 85／85 | 11-26 | dev-e | `3dad5e06` | 輔助程式 | [parity-opendesign-r8-20261126](../../tests/backup/evidence/parity-opendesign-r8-20261126/current-full-flow.json) |

### code-server

| 代號 | 情境 | 結果 | 日期 | 設備 | 驅動／產品 | 走法 | 證據 |
|---|---|---|---|---|---|---|---|
| CS1 | 原始加密 x86 展示備份走頁面；之後基準 8／8 | 105／105 | 11-28 | dev-e | `687cc9b7` | 真畫面 | [page-full-flow.json](../../tests/backup/evidence/parity-codeserver-page-20261128/page-full-flow.json)（8／8 只有說明） |
| CS2 | R8；基準 8／8 | 87／87 | 11-26 | dev-e | `f330d6c5` | 輔助程式 | [parity-codeserver-r8-20261126](../../tests/backup/evidence/parity-codeserver-r8-20261126/current-full-flow.json) |
| CS3 | D10：共用資料夾的另外兩個使用者暫停、重新掛載 | 71／71 | 11-27 | dev-e | `5209c402` | 輔助程式 | [d10-attempt2.json](../../tests/backup/evidence/focus-acceptance-20261127/d10-attempt2.json) |

### 跨服務

- **R1**（OM4）：B1 的 EMQX 部分被截短 64 位元組，檢查只擋 EMQX，Omnigent 與 Hermes 照常匯入；五個作業共用第一個作業的 systemd 單元，整串記憶體高峰 182.9 MiB（191,791,104 位元組，取樣 84 次）。舊的 70／72（測試誤以為每個作業各有單元）保留。
- **R8**（OM3）：前四次 50／53、13／15、57／60、59／63 都保留（[README](../../tests/backup/evidence/focus-acceptance-20261127/README.md)）；第五次 85／85。
- 每一次頁面跑法都記錄：轉換與還原是同一串連結作業、都在第一個作業的 systemd 單元裡（R8 是兩個應用、四個作業）；頁面發出的 Cockpit 登入值都不在紀錄與日誌（公開的固定標記另計）。
- 11-26 在 dev-d 另有轉換中取消 30／30、轉換中 SIGKILL 31／31、轉換中重開 dev-d 31／31（[parity-r1-lab-20261126](../../tests/backup/evidence/parity-r1-lab-20261126/README.md)，只有說明）。
- 失敗的嘗試都保留（DESIGN G5）：例如 R8 第 1～4 次、D10 第 1 次、Hermes 第 1 次、R4 的 http_dummy 與 H1 前兩次、Nextcloud 完整 share 第 1～4 次。

## 共通項目對照表

✔＝實機證明（括號內是上面的代號）；◐＝只證明一部分（見表下說明）；缺＝沒有實機證據；—＝不適用；略＝擁有者略過。

| 項目 | EMQX | Odoo | n8n | Nextcloud | Omnigent | LiteLLM | Hermes | Headscale | OpenDesign | code-server |
|---|---|---|---|---|---|---|---|---|---|---|
| C1 檢查 | ✔ EM1 | ✔ OD1 | ✔ N1 | ✔ NC1 | ✔ OM3 | ✔ LL1 | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C2 未確認就拒絕 | ✔ EM3、EM4 | 缺 | 缺 | ✔ NC4、NC5 | ✔ OM1 | 缺 | — | 缺 | 缺 | ✔ CS3 |
| C3 真實匯入 | ✔ EM1 | ✔ OD1 | ✔ N1 | ✔ NC1 | ✔ OM3 | ✔ LL1 | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C4 匯入後驗證 | ✔ EM2、EM5 | ✔ OD1 | ✔ N1、N2 | ✔ NC1 | ✔ OM1 | ✔ LL1 | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C5 重新啟動後 | ✔ EM2、EM5 | 缺 | ✔ N1 | ✔ NC1、NC2 | ✔ OM1 | ✔ LL1、LL2 | ✔ HE1 | ✔ HS1、HS2 | ✔ ODE1 | ✔ CS1 |
| C6 故意失敗→自動回復 | ◐ EM5 | 缺 | ✔ N1 | ✔ NC1、NC2 | ✔ OM1 | ✔ LL1、LL2 | **缺** | ✔ HS1、HS2 | ✔ ODE1 | ✔ CS1 |
| C7 用匯入前備份手動回復 | ◐ | ◐ | ◐ | ✔ NC1、NC2 | ◐ | ◐ | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C8 原狀精確回復 | ✔ EM1、EM2 | ✔ OD1 | ✔ N1 | ✔ NC1 | ✔ OM3 | ✔ LL2 | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C9 只清自己的 | ✔ EM1、EM2 | ✔ OD1 | ✔ N1 | ✔ NC1 | ✔ OM3 | ✔ LL1 | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C10 機密掃描 | ✔ EM1、EM2 | ✔ OD1 | ✔ N1 | ✔ NC1 | ✔ OM3 | ✔ LL1 | ✔ HE1 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C11 真畫面 | ✔ EM1 | ✔ OD1 | ✔ N2 | ✔ NC2、NC3 | ✔ OM3 | ✔ LL2 | ✔ HE2 | ✔ HS1 | ✔ ODE1 | ✔ CS1 |
| C12 加密的 HA 備份 | ✔ EM1 | ✔ OD1 | ✔ N2 | ✔ NC1 | ✔ OM3 | ✔ LL1、LL2 | ✔ HE1 | 缺 | ✔ ODE1 | ✔ CS1 |
| C13 未加密的 HA 備份 | 缺 | 缺 | 缺 | ✔ NC5 | 缺 | 缺 | 缺 | ✔ HS1、HS2 | 缺 | 缺 |
| C14 版本不同 | ◐ EM2 | 缺 | 缺 | 缺 | 缺 | ◐ LL1、LL2 | 缺 | 缺 | 缺 | 缺 |
| C15 ARM 主機 | 略 | 略 | 略 | 略 | 略 | 略 | 略 | 略 | 略 | 略 |
| （對照）頁面涵蓋輔助程式做過的情境 | ◐ | ✔ | ◐ | ◐ | ◐ | ◐ | ◐ | ✔ | ✔ | ◐ |

表下說明：

- **C2**：EMQX 的拒絕是在產生的來源上用產品的轉換程式做的；code-server 的拒絕發生在還原（D10：沒有指名確認就不開始還原）。Hermes 與 Omnigent 的原始 B1 沒有要確認的事項（R8 記錄確認鍵為 0），所以 Hermes 不適用；Omnigent 的拒絕來自加了額外物件的構造來源（OM1）。Odoo、n8n、LiteLLM、Headscale 的真實備份都有確認行，頁面都確認一次就匯入，沒有試過不確認；OpenDesign 的紀錄沒寫有幾條。
- **C6**：EMQX 只有 11-26 的 R4 D0（產品 `d0cfef06`，只有說明）；之後 EMQX 匯入程式改過三次（`a2069c20`、`d8a4719f`、`04ee922c`），頁面與升級兩次實測都沒有再做故意失敗。Hermes 的所有實機紀錄（包含 11-23～24 的舊世代）都只做手動回復。
- **C7**：◐ 表示退回原狀用的是事先另存的基準備份（EMQX 的 B0 與 11-19 基準、Odoo 與 n8n 與 LiteLLM 測試開始前另做的完整備份、Omnigent 的原始基準），而不是匯入時自動做的匯入前備份。Omnigent 的 OM1 目標是一次性的，測完整個移除。
- **C14**：實機各次的版本檢查都是可以直接匯入的組合（紀錄裡有「add-on 0.1.14、目標 0.22.5」「同一個核心修訂」「四個程式相同」這類檢查行）。版本不同時的提醒或擋下只有單元測試。例外：LiteLLM 是 HA 的 PostgreSQL 18 搬到這台的 17（LL1、LL2）；EMQX 證明的是匯入之後套件升級（EM2），匯入時版本不同會被產品擋下（`version.different`），這一點沒有實機。
- **C13**：讀 HA 備份與解密是共用程式。目前引擎的未加密實機只有 Headscale 與 Nextcloud S5（產生的來源）；Hermes、Omnigent 的未加密備份只在 11-23～24 的舊引擎上測過（附錄）。
- **C15**：ARM 製作的 HA 備份在目前引擎只有 EMQX 的檢查（EM5，沒有匯入）；匯入只在 11-23～24 的舊引擎（附錄）。先前用真實 RPi5 備份的 ARM 備份接受（PR #22，`bb23531f`）不受影響。
- **頁面涵蓋**：缺了哪些情境，見「還沒證明的事」第 3 點。Odoo 標 ✔ 是因為頁面跑法比輔助程式多，但兩者都沒有重新啟動與故意失敗。

## 狀態文件逐項核對

**不一致（本次已改正）**

1. Headscale 真畫面 125／125 → 123／123（第 3 行與 Headscale 列）。依據：`page-full-flow.json` 的總數行是 `headscale full flow x86: 123/123 PASS`。紀錄裡有 124 行以「: PASS」結尾，加上「mutation lock acquired: PASS (waited 0 s)」共 125 行；多出的兩行是外層的「source tree committed」與「mutation lock acquired」，不在驅動程式的總數裡。同一支程式的 HS2 也有這兩行，總數寫的是 96／96；LiteLLM LL3 同樣多這兩行，總數是 80／80。
2. R9 一行：PR #23 已合併（`ee520d49`，2026-11-28 04:51），`f341143e` 與 `4cf97c25` 都在其中；#24、#25 也已合併。

另外更新：第 3 行「仍待：…與證據總核對」，證據總核對就是本文件，改為指向這裡；共通驗收仍待。

**只有說明或參照、沒有提交原始紀錄的數字**（數字本身沒有矛盾，但只能看到文字）

- EMQX R4 D0 的 31／31、56／56、76／76、11／11（EM5）；Odoo 冷叢集 37／37（OD2）；Omnigent R7 的原始 B1 那一次（OM2）。
- n8n 34／34（N3）與 Nextcloud no-share 36／36（NC7）：只在別的檔案裡被引用。LiteLLM「既有原始 HA 應用流程 80／80」：提交的只有 11-24 舊引擎那一次（LL3）。
- OpenDesign 頁面後的 7／7、code-server 頁面後的 8／8：只寫在 README（較早幾次的基準檢查有 JSON：OpenDesign 的 ODE2、ODE3，code-server 的 CS2）。
- LiteLLM「匯入後 11 項及重新啟動後 12 項」；n8n「62 份既有備份、11 份既有上傳」；LiteLLM「13 份既有備份、8 份既有上傳、原有八個容器」：提交的檔案裡找不到。
- PR #23 的 GitHub 檢查「3,835 項、1 項錯誤」：只寫在 `f341143e` 的提交說明裡。
- EMQX 升級（EM2）用的產品 commit 只在私人租約裡。
- n8n 85／85 的第 85 個檢查名稱被紀錄程式丟掉（見 n8n 一節）。

**commit 名稱**

- 狀態文件引用的 20 個 commit 都存在。18 個在 main；`550478ae`（Nextcloud 驅動程式）與 `6daaa15c` 不在 main，但 `git patch-id` 和 main 的 `1817feec`、`9e085a09` 相同（文件本來就寫了 `6daaa15c` 與 `9e085a09` 相同），驅動程式檔案也逐位元相同。
- 從證據檔與 README 取出的 commit 有 22 個不在 main（含上面的 `550478ae`；例如產品 `ce8c4cfb`、`bfe7b914`，驅動 `687cc9b7`、`5209c402`、`a82a086f`），每一個在 main 都有 `git patch-id` 相同的對應提交（`aaadebc9`、`7115bbaa`、`18f60897`、`7f0b8b27`、`c0fff26e`…）。`c01c897`、`ea5886c` 是 EMQX 套件 repo 的 commit，本來就不在這裡。

**測完之後產品程式還改了什麼**

- `4eb41e29` 之後只有兩個產品改動：`50a29370`（只動 `ha_nextcloud.py`，NC2～NC5 都已包含）與 `7a2023e8`（`podman.py`：資料庫登入被拒時說出真正原因，不再說「還沒有準備好」，也不再重試）。
- 除了 NC2（裝的就是現在 main 的產品程式），其餘真畫面跑法的產品程式都沒有 `7a2023e8`。它只改錯誤說明與重試分類，不影響成功的路徑。
- `ce8c4cfb` 與 `4eb41e29` 只差在 `ha_n8n.py`、`ha_nextcloud.py`；`bfe7b914` 只差在 `ha_instance_access.py`、`ha_litellm.py`、`ha_nextcloud.py`。差的那一段是 PostgreSQL 17 的 `MAINTAIN` 權限，n8n 用 PostgreSQL 16，用不到。所以各服務自己的匯入程式和測試時相同。
- 較早的紀錄（HE1 `0d04a097`、OM1 `3dad5e06`、HS2 `6ccf7106`、CS2 `f330d6c5`）之後，共用的引擎檔案（`archive.py`、`adapters/quadlet_postgres.py` 等，HE1、OM1、CS2 之後還有 `hasqlite.py`）有改。code-server、Headscale 的頁面跑法已在新程式上重跑全部情境；Omnigent 與 Hermes 的重新啟動與回復情境還沒有在新程式上重跑。

## 還沒證明的事

1. **Odoo 只用替代映像**：dev-c 沒有原始租戶的映像，三次證據都是替代映像，不算原始租戶驗收。Odoo 也沒有重新啟動、故意失敗、未確認就拒絕的實機，退回原狀用的是基準備份。
2. **ARM 本輪略過**（擁有者 2026-11-28）：沒有任何 ARM 主機上的驗收。ARM 製作的備份在目前引擎只做過 EMQX 的檢查。
3. **頁面跑法少於輔助程式跑法的服務**：
   - n8n：頁面跑的是應用流程，完整執行個體流程（重新啟動、故意失敗自動回復、不一致備份被拒、其他資料庫與角色保留）只走輔助程式。
   - Omnigent：頁面（R8）只證明資料換成 HA 的、再還原原狀；重新啟動、自動回復、未確認被拒、登入與代理程式等檢查只在 OM1（一次性目標、較舊程式）。
   - Hermes：頁面只證明 HA 的工作階段取代原本的標記；重新啟動、手動回復、全文搜尋等只在 HE1。
   - EMQX：頁面沒有重新啟動、故意失敗，也沒有 MQTT 行為檢查（保留訊息、ACL 拒絕、規則）；這些只在 EM2、EM5。
   - LiteLLM：「轉換之後才寫入其他資料庫」的見證在頁面之前就做了，所以頁面只證明既有的其他資料庫、角色與密碼沒被動到。
   - Nextcloud：略過項目（NC4）與伺服器端加密（NC5）只走輔助程式；頁面一次勾全部確認行，做不出「只確認一行」的情形。
   - code-server：D10（共用資料夾的其他使用者）只走輔助程式。
4. **Hermes 從未做過「故意失敗→自動回復」**。
5. **有確認行卻沒試過不確認**：Odoo、n8n、LiteLLM、Headscale、OpenDesign（OpenDesign 的紀錄沒寫有沒有確認行）。
6. **退回用基準備份而不是匯入前備份**：EMQX、Odoo、n8n、Omnigent、LiteLLM。
7. **版本不同**：除了 LiteLLM 的 PostgreSQL 18→17 與 EMQX 匯入後升級，各服務「HA 與這台版本不同」的提醒或擋下都只有單元測試。
8. **未加密的 HA 備份**：目前引擎只有 Headscale 與 Nextcloud S5；Headscale 反過來沒有加密 HA 備份的實機。
9. **EMQX**：R4 各情境的套件 smoke.sh 沒有逐一執行；預設管理員的實體網路暴露沒有測；自動回復只在 11-26 的較舊程式上做過。
10. **範圍外、狀態文件已列為待辦的**：OpenDesign 的提供者登入、配對與重開機範圍；code-server 的提供者登入、Omnigent／Paseo 配對、有 share 資料夾的工作區、主機重開機；Omnigent 的瀏覽器與提供者登入。
11. **紀錄本身的缺口**：上一節「只有說明或參照」列出的數字，以及 n8n 紀錄程式丟掉的那一個檢查名稱。

## 附錄：較早世代的實機證據（2026-11-23～24，HAOS 對齊前）

這些是 11-25 產品行為改變之前的結果，只核對了總數行，不能代替上面的證據。總表在 [final-verify-20261124](../../tests/e2e/lab/evidence/final-verify-20261124/README.md)。

| 服務 | 結果 | commit | 證據 |
|---|---|---|---|
| Hermes | x86 加密 90／90；x86 未加密 105／105 | `4353892e`；`dbdf399c` | [hermes-real-20261123](../../tests/e2e/lab/evidence/hermes-real-20261123/status.json) |
| Omnigent | x86 加密 112／112；x86 未加密 112／112；ARM 製作的備份加密與未加密各 112／112 | `4353892e` 等 | [omnigent-product-20261123](../../tests/e2e/lab/evidence/omnigent-product-20261123/README.md) |
| LiteLLM | 80／80 | `4353892e` | LL3 |
| EMQX | 匯入 101／101、回復與清理 101／101 | `ccc3ed75` | [emqx-product-20261123](../../tests/e2e/lab/evidence/emqx-product-20261123/attempt-final-verify-01-r2.json) |
| Headscale | ARM 製作的備份完整流程 101／101 | `70bcf6ff` | [services-a-real-20261123](../../tests/e2e/lab/evidence/services-a-real-20261123/headscale-fullflow-arm-attempt2-final-verify-r2.json) |
| Odoo＋n8n | ARM 製作的備份 133／133；x86 94／94；x86 修正 40／40 | `0718f774`；`4353892e` | [odoo-n8n-final-20261123](../../tests/e2e/lab/evidence/odoo-n8n-final-20261123/README.md) |
| Nextcloud | 完整 share 113／113；沒有 share 時當時是拒絕 34／34 | `6a67eefa`；`7e969f0` | [nextcloud-import-20261123](../../tests/e2e/lab/evidence/nextcloud-import-20261123/README.md) |
| OpenDesign | 85／85 | `f4a3c16c` | [opendesign-import-20261123](../../tests/e2e/lab/evidence/opendesign-import-20261123/opendesign-x86-attempt3.json) |
| code-server | 87／87 | `6cdae620` | [codeserver-import-20261123](../../tests/e2e/lab/evidence/codeserver-import-20261123/codeserver-x86-attempt1.json) |
