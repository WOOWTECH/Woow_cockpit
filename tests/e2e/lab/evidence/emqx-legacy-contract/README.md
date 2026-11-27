# Legacy public EMQX contract suite — 2026-11-20

Source: `fdaaaa9`. Command used SUBSET=test_ha_emqx.py with the existing isolated
run_tests.py harness. Actual full output is current.txt.
Current module has 13 tests: 3 pass, 9 failures, 1 error, zero skipped.
This is NOT an all-green suite and none of these failures has been skipped,
converted into a pass, or fixed by disabling a public guard.

Failure classification from the actual stack/assertions:

| Test | Actual conflict |
| --- | --- |
| test_a_clean_backup | Expected public ok=True; receives PRESERVATION_BLOCKER |
| test_a_hot_backup_is_tried_and_named | Public success assertion fails while preservation gate remains |
| test_an_ip_node_name_needs_no_host_line | Public success assertion fails while preservation gate remains |
| test_blockers | Expected version blocker first; preservation blocker now comes first |
| test_a_failed_export_stops_the_conversion_with_the_advice | Guard stops before export; expected later export error unreachable |
| test_a_partial_import_stops_the_conversion | Guard stops before import; expected partial-import error unreachable |
| test_an_import_that_would_open_anonymous_login_is_refused | Guard stops before import; expected anonymous-policy error unreachable |
| test_lost_rows_stop_the_conversion | Guard stops before import; expected row-loss error unreachable |
| test_the_strict_settings_must_come_back | Guard stops before import; expected restoration-error assertion unreachable |
| test_the_whole_conversion | BackupError raised at public convert guard, before candidate invocation |

These are stale success/error-order contracts against intentionally disabled public
entry points, not a claim that the public feature works. Internal candidate tests
and the real synthetic broker evidence cover distinct paths. They cannot turn
this suite green or authorize real HA restoration. Before release, public feature
policy and these success contracts must be reconciled after required safety review
and acceptance; until then retain this explicit failed status.
