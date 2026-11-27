T = ('tests.backup.test_ha_pg_stdin',)
MUTS = [
 ('M59', T, "    listed = check_listing(text)\n", "    listed = toc_entries(text)[0]\n"),
 ('M60', T, "    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:\n", "    if held_back is None:\n"),
 ('M109', T, "    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:\n", "    if held_back is None or not held_back <= lowest + LISTING_SLACK:\n"),
 ('M110', T, "    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:\n", "    if held_back is None or not lowest <= held_back:\n"),
 ('M111', T, "LISTING_SLACK = 9      # entries beyond", "LISTING_SLACK = 60     # entries beyond"),
 ('M112', T, "    lowest = len(ARCHIVE_SETTINGS) - shown\n", "    lowest = len(ARCHIVE_SETTINGS)\n"),
 ('M113', T, "    work.log(f'已檢查資料庫匯出檔的項目清單：共 {listed} 項（檔頭記載 {toc_entries(text)[1]} 項）。')\n", ""),
]
