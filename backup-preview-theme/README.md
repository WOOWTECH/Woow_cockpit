# 備份設計預覽：Cockpit 主題同步

此套件只為現有的 `woowbackupdesign` 靜態示意原型提供深淺色樣式，不會安裝或改動備份引擎。原型的互動仍為示意，沒有實際備份或還原能力。

執行 `sudo python3 backup-preview-theme/install.py`。安裝器會備份原有 index 和既有主題檔，再加入兩個獨立主題檔；原有程式及資料不會覆蓋。若原型尚未安裝或 index 結構不同，安裝器會拒絕變更。
