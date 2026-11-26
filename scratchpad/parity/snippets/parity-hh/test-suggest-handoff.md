# HH reconciliation for shared `test_suggest`

At HH base `9da33013`, the targeted `tests.backup.test_suggest` run finished with 65 tests, one failure and one error. Both refer to `ReferenceHostTests.test_the_default_drafts_are_the_entries_the_imports_fill`: its assertion expects the Hermes `cold` variant to raise `BackupError`, then accesses `caught.exception` after that assertion fails.

The current Hermes target intentionally accepts a cold database volume and carries it unchanged (H-03). `tests.backup.test_ha_hermes.LayoutTests.test_a_cold_entry_and_a_folder_are_carried_as_they_are` passes. The shared expectation should accept Hermes `cold`, continue rejecting Hermes `instance`, and continue applying n8n's own mode rules. The combined integration owner can make that edit in the shared test.

There is also a passing but outdated assertion in `test_an_installed_cold_entry_keeps_its_mode_and_is_told_what_to_choose`: `suggest._selected_variant` still says a cold Hermes entry cannot import from HA and asks for single-database mode. The message should describe the preferred mode without claiming cold import is impossible. This lane has made no shared `test_suggest` or `suggest.py` edits.
