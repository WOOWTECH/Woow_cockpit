ODOO iteration 3 (OD-OWNER-1735), 2026-11-25 20:xx
- The finding: the pg-stdin F4 check of iterations 1-2 (TOC Entries = lines + 3, exact) refuses the only real pg_restore -l listing on the host
  (PostgreSQL 16.15, a Nextcloud database, the Nextcloud lane's probe of 2026-11-24: 1131 entry lines under "TOC Entries: 1136").
  Fix 6f35b77 (+ docstring be07df7): a slack of 9 over the settings not shown; the job log has the two numbers.
- muts_toc.py = the 7 hand mutants of the fix (M59 M60 M109-M113), run with hm.py in a COPY of the tree: all caught (survivors: none).
  mutations.py (the sweep) has the same mutants (113 + 2 controls; `--check-text` finds every text once).
- watch.sh = the load gate in front of run.sh (main's 19:55 rule: <= 6 heavy.sh waiting and the 5-minute load < 20, seen twice).
- Cross-checks without any change needed: AST comparison of all tmp.* / sink.* / module-function calls of ha_odoo.py with the real signatures (88 calls, 0 mismatches),
  work.* attributes against haimport.Work, superuser_kinds/filter_toc on the real listing (no false kind; EXTENSION and its COMMENT dropped), the merge of the lane tip into
  parity-int/combined-20261125 (clean, git merge-tree).
