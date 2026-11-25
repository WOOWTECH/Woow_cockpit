#!/usr/bin/env python3
"""Builds ../ha_parity_rows.json (the snippet of the lane OMNIGENT; DESIGN G1) from the table below.
usage: python3 build_rows.py > ../ha_parity_rows.json     (then merge + check, see ../NOTES.txt)"""
import json
import sys

M = 'tests/backup/test_ha_omnigent.py::'
T = 'tests/backup/test_ha_omnigent_trusted.py::'
C = 'tests/backup/test_ha_omnigent_candidate.py::'
S = 'tests/backup/test_ha_omnigent_server_volume.py::'
ROW, CONV, CHECK, SKIP = M + 'RowTests.', M + 'ConvertTests.', M + 'CheckTests.', M + 'SkippedLineTests.'
TRUSTED, REFUSAL, SCAN = M + 'TrustedSchemaTests.', M + 'RefusalTests.', M + 'ScanTests.'
SNAP, CAND, VOL = T + 'SnapshotScriptTests.', C + 'CandidateFlowTests.', S + 'ServerVolumeTests.'


def triple(kind):
    return [f'{SKIP}test_{kind}_not_confirmed', f'{SKIP}test_{kind}_confirmed', f'{SKIP}test_{kind}_one_more']


SKIPPED = {'omnigent.skipped': 'confirm'}
VERSIONS = {'omnigent.version-different': 'notice', 'version.addon-unknown': 'notice'}
VERSION_TESTS = [CHECK + 'test_versions', CONV + 'test_a_version_that_does_not_match_is_no_reason_to_stop_the_conversion',
                 CONV + 'test_another_structure_version_stops_the_conversion_itself']
READ_AGAIN = [ROW + 'test_a_database_that_is_not_running_is_started_to_be_read_and_put_back',
              ROW + 'test_this_devices_structure_is_read_again_when_the_answer_is_odd',
              ROW + 'test_this_devices_structure_that_is_never_readable_stops_this_app']
STEADY = TRUSTED + 'test_a_structure_that_is_still_moving_is_waited_for'
RETRY = [SNAP + 'test_a_snapshot_that_was_not_taken_is_tried_again_with_a_longer_wait',
         SNAP + 'test_a_snapshot_that_is_never_taken_stops_after_three_tries']

ROWS = {
    # ---- auto
    'O-01': ('done', {}, [ROW + 'test_the_dump_runs_as_a_spare_id_when_the_list_has_none',
                          ROW + 'test_no_id_at_all_stops_the_conversion_before_the_dump',
                          CONV + 'test_the_dump_user_is_one_the_owners_namespace_can_represent'], ''),
    'O-02': ('done', {'omnigent.hardlinks-copied': 'auto'}, [
        SCAN + 'test_links_in_the_cluster_are_copied_and_out_of_the_store_are_left_out',
        ROW + 'test_hard_links_in_has_database_folder_are_copied_as_files',
        ROW + 'test_a_hard_link_with_no_file_behind_it_is_asked_about_and_stops_only_this_app'], ''),
    'O-07': ('done', {'omnigent.extras-carried': 'auto'}, [
        ROW + 'test_this_devices_other_volumes_go_along_as_they_are',
        ROW + 'test_a_missing_or_doubled_volume_still_stops_with_extra_ones_around',
        REFUSAL + 'test_a_device_that_is_not_set_up_like_the_package_is_no_target'], ''),
    'O-18': ('done', {'omnigent.pg-newer': 'stop'}, [
        ROW + 'test_an_image_without_pg_major_is_asked_through_its_database',
        ROW + 'test_a_postgresql_newer_than_the_image_stops_this_app', REFUSAL + 'test_what_has_database_must_be'], ''),
    'O-25': ('done', VERSIONS, VERSION_TESTS, ''),
    'O-32': ('done', {}, [SNAP + 'test_a_damaged_columns_line_is_read_again_and_then_refused',
                          TRUSTED + 'test_snapshot_columns_must_be_the_live_ones'], ''),
    'O-33': ('done', {}, [SNAP + 'test_a_damaged_columns_line_is_read_again_and_then_refused',
                          TRUSTED + 'test_snapshot_columns_must_be_the_live_ones'], ''),
    'O-40': ('done', {'omnigent.target-unreadable': 'stop'}, READ_AGAIN, ''),
    'O-41': ('done', {'omnigent.target-unreadable': 'stop'}, READ_AGAIN, ''),
    'O-42': ('done', {}, [STEADY, TRUSTED + 'test_a_revision_that_moved_since_the_check_stops'], ''),
    'O-43': ('done', {}, [STEADY, TRUSTED + 'test_ddl_during_the_capture_stops'], ''),
    'O-44': ('done', {'omnigent.extension-version': 'auto'}, [
        ROW + 'test_a_newer_extension_version_of_the_new_cluster_is_no_difference',
        ROW + 'test_another_set_of_extensions_still_stops', ROW + 'test_the_drift_rule_on_its_own'], ''),
    'O-49': ('done', VERSIONS, VERSION_TESTS, ''),
    'O-50': ('done', {}, [ROW + 'test_the_conversion_says_what_the_check_said',
                          ROW + 'test_the_first_stop_of_the_conversion_is_the_check_s'], ''),
    'O-58': ('done', {}, RETRY, ''),
    'O-59': ('done', {}, RETRY, ''),
    # ---- skip_one
    'O-03': ('done', SKIPPED, triple('links') + [SCAN + 'test_links_in_the_cluster_are_copied_and_out_of_the_store_are_left_out'], ''),
    'O-10': ('done', {'omnigent.no-database': 'stop'}, [REFUSAL + 'test_answers_that_are_not_what_was_asked_for_stop_the_job'], ''),
    'O-12': ('done', SKIPPED, triple('tables'), ''),
    'O-14': ('done', SKIPPED, triple('objects'), ''),
    'O-15': ('part', SKIPPED, triple('superuser_objects') + [SKIP + 'test_nothing_of_the_superuser_kinds_is_ever_selected'],
             'code and unit tests done; the security re-review of DESIGN H-c was done by the lane itself (evidence README), an independent re-review and the real run (R7) are still to do'),
    'O-16': ('done', SKIPPED, triple('extensions'), ''),
    'O-21': ('done', SKIPPED, triple('locations') + [
        ROW + 'test_the_rule_of_an_artifact_key',
        ROW + 'test_the_locations_that_could_leave_the_store_are_cleared_by_the_role_without_privileges',
        ROW + 'test_a_location_that_is_still_unsafe_after_the_clearing_stops_the_conversion'], ''),
    'O-28': ('done', {**SKIPPED, 'omnigent.entries-skipped': 'notice'}, triple('tables') + [
        CONV + 'test_a_name_with_a_line_break_cannot_add_an_entry',
        T + 'TrustedDataTests.test_strict_list_takes_each_trusted_name_once'], ''),
    # ---- remove
    'O-13': ('done', {}, [ROW + 'test_a_table_that_ha_lacks_is_found_by_the_comparison_of_the_columns',
                          REFUSAL + 'test_what_has_database_must_be'], ''),
    'O-23': ('done', {'version.addon-unknown': 'notice'}, [CHECK + 'test_versions'], ''),
    'O-24': ('done', {'version.target-unknown': 'notice'}, [REFUSAL + 'test_a_live_version_that_cannot_be_read_is_no_version'], ''),
    'O-31': ('open', {}, [], 'left as it is on purpose: the check of the revision is the injection guard of a value put into the snapshot shell script (test_invalid_revision_rejected_before_capture) and cannot be reached in the normal flow (O-19 makes HA equal to this device first), so the customer never sees it'),
    'O-54': ('done', {}, [CONV + 'test_a_cluster_that_did_not_stop_cleanly_is_never_exported'], ''),
    'O-56': ('done', {}, [CAND + 'test_the_compatibility_entry_needs_no_promise_about_ddl',
                          CAND + 'test_the_product_conversion_itself_refuses_a_schema_that_moves'], ''),
    'O-57': ('done', {}, [VOL + 'test_root_metadata_change_is_no_reason_to_stop'], ''),
    'O-61': ('done', {}, [ROW + 'test_a_huge_pg_version_file_is_read_by_its_start_only'], ''),
    # ---- warn
    'O-09': ('done', {'omnigent.accounts-unreadable': 'notice'}, [
        ROW + 'test_this_devices_accounts_that_cannot_be_read_are_not_kept_and_the_import_goes_on',
        ROW + 'test_a_read_that_fails_once_is_read_again', ROW + 'test_a_read_that_is_refused_stops_this_app'], ''),
    'O-20': ('done', {'omnigent.cookie-missing': 'notice'}, [
        ROW + 'test_a_missing_login_key_is_a_notice_and_nothing_of_it_is_carried',
        ROW + 'test_an_empty_or_huge_login_key_is_no_key'], ''),
    'O-22': ('done', {'omnigent.files-missing': 'confirm'}, [
        ROW + 'test_missing_files_not_confirmed', ROW + 'test_missing_files_confirmed', ROW + 'test_missing_files_one_more',
        ROW + 'test_when_no_file_of_the_store_is_there_at_all_the_line_says_so'], ''),
    'O-48': ('done', {'omnigent.secrets-unregistered': 'notice'}, [
        TRUSTED + 'test_unregistered_quadlet_secrets_are_told_and_the_conversion_goes_on',
        CAND + 'test_unregistered_quadlet_secret_is_a_notice_not_a_refusal'], ''),
}

if __name__ == '__main__':
    ids = ['O-01', 'O-02', 'O-07', 'O-18', 'O-25', 'O-32', 'O-33', 'O-40', 'O-41', 'O-42', 'O-43', 'O-44', 'O-49', 'O-50',
           'O-58', 'O-59', 'O-03', 'O-10', 'O-12', 'O-14', 'O-15', 'O-16', 'O-21', 'O-28', 'O-13', 'O-23', 'O-24', 'O-31',
           'O-54', 'O-56', 'O-57', 'O-61', 'O-09', 'O-20', 'O-22', 'O-48']
    assert sorted(ids) == sorted(ROWS), sorted(set(ids) ^ set(ROWS))
    rows = {i: {'status': ROWS[i][0], 'issues': ROWS[i][1], 'tests': ROWS[i][2], 'note': ROWS[i][3]} for i in ids}
    sys.stdout.write(json.dumps({'lane': 'OMNIGENT', 'rows': rows}, ensure_ascii=False, indent=1) + '\n')
