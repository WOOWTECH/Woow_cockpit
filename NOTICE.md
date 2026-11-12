# 來源、授權與品牌

本 repository 包含 WOOWTECH 品牌資產、部署程式、修改後的 cockpit-podman 前端及第三方字型／圖示。公開存取不等於所有檔案有相同授權；本專案沒有替公司標誌、品牌或新增程式碼宣告一份統一的開源授權。商標及官方 SVG 保留 WOOWTECH 的權利。對外再散布時應保留各來源的授權文字，並確認品牌使用權限。

| 內容 | 來源與授權 |
| --- | --- |
| 官方 SVG／favicon | 使用者提供的 woowtech 品牌資產；不重繪 |
| Poppins | Google Fonts／上游作者，SIL OFL 1.1；`branding/fonts/LICENSE-Poppins.txt` |
| Outfit | Google Fonts／上游作者，SIL OFL 1.1；`branding/fonts/LICENSE-Outfit.txt` |
| Noto Sans TC | Google Fonts／上游作者，SIL OFL 1.1；`branding/fonts/LICENSE-NotoSansTC.txt` |
| Yellowtail | Google Fonts／上游作者，Apache 2.0；`branding/fonts/LICENSE-Yellowtail.txt` |
| MDI paths | Pictogrammers Material Design Icons；圖示 Apache 2.0，相關程式 MIT，見 `licenses/MDI-LICENSE.txt` 與 `licenses/Apache-2.0.txt` |
| Cockpit 核心 | 由 Ubuntu 套件提供，保留其套件授權 |
| 修改後 cockpit-podman124／Cockpit 共用元件 | LGPL-2.1-or-later；相應來源、修補及 lockfile 見 `native/podman/`，授權文字見 `native/podman/dist/licenses/` |
| 原生 bundle 的 PatternFly／React／xterm 等 | 保留上游與各 npm 套件授權；`native/podman/dist/index.js.LEGAL.txt` 及 `dist/licenses/` |
| Playwright | 可選的開發依賴，npm 套件自帶授權；不隨設備執行時部署 |

Poppins、Noto Sans TC、Yellowtail 是品牌授權字型的替代品。Outfit 為指定字型。不能把這些替代品宣稱為原授權字型。

官方資料：[MDI license](https://github.com/Templarian/MaterialDesign/blob/master/LICENSE)、[Cockpit repository](https://github.com/cockpit-project/cockpit)。

`native/podman/managed-owners.js` 與原生程式修補依 LGPL-2.1-or-later 提供；詳見該目錄 README 的相應來源與重建流程。這項授權不授予 WOOWTECH 商標使用權。
