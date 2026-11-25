#!/usr/bin/env python3
"""Builds snippets/parity-nextcloud/ha_parity_rows.json (NEXTCLOUD lane, NC-OWNER-1905): what became of every row of the lane.
Run:  python3 build_rows.py <snippet dir>
"""
import json
import sys
from pathlib import Path

T = 'tests/backup/test_ha_nextcloud.py::'
CF, DD, CT, CV, LT = (T + name + '.' for name in ('ConfigTests', 'DataDirTests', 'CheckTests', 'ConvertTests', 'LiveTargetTests'))


def three(prefix):
    return [CT + f'{prefix}_not_confirmed_stop{"s" if prefix.endswith(("period",)) else ""}_only_this_app']


# the three steps of a line to confirm (DESIGN G1), by the names of the tests
STEPS = {
    'nextcloud.no-share': [CT + 'test_no_share_folder_not_confirmed_stops_only_this_app',
                           CT + 'test_no_share_folder_confirmed_goes_on_with_an_empty_data_folder',
                           CT + 'test_no_share_folder_one_more_name_asks_again'],
    'nextcloud.no-datadir': [CT + 'test_no_data_folder_or_marker_not_confirmed_stops_only_this_app',
                             CT + 'test_no_data_folder_or_marker_confirmed_goes_on',
                             CT + 'test_no_data_folder_or_marker_one_more_name_asks_again',
                             CT + 'test_a_folder_without_the_marker_is_started_again_empty'],
    'nextcloud.datadir-elsewhere': [CT + 'test_users_files_in_a_place_a_backup_never_holds_not_confirmed_stop_only_this_app',
                                    CT + 'test_users_files_in_a_place_a_backup_never_holds_confirmed_go_on',
                                    CT + 'test_users_files_in_a_place_a_backup_never_holds_one_more_name_asks_again'],
    'nextcloud.symlinks-skipped': [CT + 'test_symlinks_of_the_users_not_confirmed_stop_only_this_app',
                                   CT + 'test_symlinks_of_the_users_confirmed_are_left_out_the_rest_moves',
                                   CT + 'test_symlinks_of_the_users_one_more_name_asks_again'],
    'nextcloud.htaccess-skipped': [CT + 'test_htaccess_files_of_the_users_not_confirmed_stop_only_this_app',
                                   CT + 'test_htaccess_files_of_the_users_confirmed_are_left_out_the_rest_moves',
                                   CT + 'test_htaccess_files_of_the_users_one_more_name_asks_again'],
    'nextcloud.server-side-encryption': [CT + 'test_server_side_encryption_not_confirmed_stops_only_this_app',
                                         CT + 'test_server_side_encryption_confirmed_goes_on',
                                         CT + 'test_server_side_encryption_one_more_name_asks_again'],
    'nextcloud.db-objects-skipped': [CT + 'test_functions_and_triggers_of_other_apps_not_confirmed_stop_only_this_app',
                                     CT + 'test_functions_and_triggers_of_other_apps_confirmed_are_left_out_and_listed',
                                     CT + 'test_functions_and_triggers_of_other_apps_one_more_name_asks_again'],
    'nextcloud.schemas-skipped': [CT + 'test_other_schemas_not_confirmed_stop_only_this_app',
                                  CT + 'test_other_schemas_confirmed_only_the_schema_public_is_moved',
                                  CT + 'test_other_schemas_one_more_name_asks_again'],
}

ROWS = {
    'NC-04': ('done', {'target.service-started': 'auto', 'target.service-failed': 'stop'},
              [LT + 'test_a_stopped_nextcloud_and_database_are_started_to_be_read_and_put_back',
               LT + 'test_what_cannot_be_started_stops_only_nextcloud',
               LT + 'test_the_redis_of_this_device_is_started_for_the_conversion_too'], ''),
    'NC-05': ('done', {'nextcloud.live-config-php': 'auto', 'nextcloud.live-config-unreadable': 'stop'},
              [LT + 'test_a_config_php_that_is_not_plain_data_is_read_by_this_devices_php',
               LT + 'test_a_config_php_that_not_even_its_own_php_gives_stops_only_nextcloud'], ''),
    'NC-07': ('done', {'nextcloud.db-role-created': 'auto', 'nextcloud.db-role-unusable': 'stop'},
              [LT + 'test_a_missing_role_is_made_from_the_password_in_config_php',
               LT + 'test_a_role_that_cannot_be_made_stops_only_nextcloud',
               LT + 'test_a_role_without_a_usable_password_keeps_its_rights_and_gets_a_new_verifier'], ''),
    'NC-08': ('done', {'nextcloud.db-role-hand-over': 'auto'},
              [LT + 'test_a_superuser_role_is_loaded_by_a_plain_one_and_handed_over',
               LT + 'test_a_superuser_role_that_owns_nothing_after_the_hand_over_stops_the_conversion',
               LT + 'test_the_clusters_own_superuser_as_nextcloud_role_gets_this_devices_verifier',
               LT + 'test_a_plain_role_is_not_touched_by_any_of_it'], ''),
    'NC-09': ('part', {'nextcloud.office-settings-unread': 'notice'},
              [LT + 'test_office_settings_that_cannot_be_read_are_a_reminder',
               LT + 'test_the_cached_collabora_answers_that_cannot_be_read_are_a_reminder_too'],
              'Office settings and the cached Collabora answers: done. The lists of roles and extensions of this device still stop when '
              'unreadable (the checks after the conversion compare them; leaving them out would weaken those checks).'),
    'NC-12': ('done', {'nextcloud.config-unreadable': 'stop', 'nextcloud.config-missing': 'stop'},
              [CF + 'test_other_ways_to_write_a_value_are_still_values',
               CF + 'test_refuses_anything_that_is_not_data',
               CT + 'test_a_hand_edited_config_php_with_double_quotes_and_constants_is_read',
               CT + 'test_a_config_php_that_is_not_plain_data_or_is_missing_stops_only_nextcloud'], ''),
    'NC-13': ('done', {'nextcloud.not-installed': 'stop'},
              [CT + 'test_a_nextcloud_that_was_never_set_up_stops_only_nextcloud'], ''),
    'NC-14': ('done', {'nextcloud.maintenance-mode': 'notice', 'nextcloud.maintenance-upgrading': 'stop'},
              [CF + 'test_maintenance_mode_is_a_reminder_unless_an_upgrade_may_have_been_half_done',
               CT + 'test_maintenance_mode_and_an_unreadable_version_do_not_stop_the_import'], ''),
    'NC-20': ('done', {'nextcloud.version-unreadable': 'notice'},
              [CF + 'test_an_unreadable_version_of_ha_is_taken_from_the_add_on',
               CT + 'test_maintenance_mode_and_an_unreadable_version_do_not_stop_the_import'], ''),
    'NC-22': ('done', {'nextcloud.no-share': 'confirm'}, STEPS['nextcloud.no-share'], ''),
    'NC-23': ('done', {'nextcloud.no-datadir': 'confirm'}, STEPS['nextcloud.no-datadir'], ''),
    'NC-25': ('done', {'nextcloud.datadir-elsewhere': 'confirm'},
              STEPS['nextcloud.datadir-elsewhere'] + [CT + 'test_a_path_with_spaces_or_chinese_is_found_in_the_backup'], ''),
    'NC-26': ('done', {'nextcloud.symlinks-skipped': 'confirm'}, STEPS['nextcloud.symlinks-skipped'], ''),
    'NC-27': ('done', {'nextcloud.htaccess-skipped': 'confirm'}, STEPS['nextcloud.htaccess-skipped'], ''),
    'NC-28': ('done', {'nextcloud.server-side-encryption': 'confirm'}, STEPS['nextcloud.server-side-encryption'], ''),
    'NC-29': ('done', {'nextcloud.hardlinks-copied': 'auto'},
              [DD + 'test_a_hard_link_to_a_file_that_is_not_moved_is_copied',
               DD + 'test_a_hard_link_the_reader_hands_out_without_its_file_still_stops_the_folder',
               DD + 'test_a_link_to_a_file_outside_the_folder_or_a_secret_is_not_copied_in'], ''),
    'NC-30': ('done', {'nextcloud.no-database': 'stop'},
              [CT + 'test_a_backup_without_the_database_stops_only_nextcloud'], ''),
    'NC-32': ('done', {}, [CT + 'test_a_newer_postgresql_of_ha_is_tried_and_a_refused_restore_says_why'], ''),
    'NC-38': ('part', {'nextcloud.db-objects-skipped': 'confirm', 'nextcloud.db-objects': 'stop'},
              STEPS['nextcloud.db-objects-skipped'] + [CT + 'test_what_cannot_be_left_out_is_refused_unread'],
              'Functions and triggers of other apps (what Memories makes) are left out and listed, the data moves; any other foreign '
              'object still stops. NOT built: the allow-list of known apps whose objects are copied verbatim (needs their real '
              'definitions from a real Nextcloud with the app).'),
    'NC-39': ('done', {'nextcloud.extension-enabled': 'auto', 'nextcloud.extension-missing': 'stop'},
              [CT + 'test_an_extension_this_devices_image_has_is_enabled_first',
               CT + 'test_an_extension_this_devices_image_does_not_have_stops_only_nextcloud'], ''),
    'NC-40': ('done', {'nextcloud.schemas-skipped': 'confirm'}, STEPS['nextcloud.schemas-skipped'], ''),
    'NC-45': ('part', {'nextcloud.db-objects-skipped': 'confirm'},
              [CT + 'test_the_dump_may_not_hold_more_than_was_confirmed',
               CT + 'test_procedures_and_aggregates_are_programs_too',
               CT + 'test_a_program_that_stays_in_the_new_cluster_stops_the_conversion',
               CV + 'test_a_dump_with_kinds_nextcloud_never_creates_is_refused_before_the_restore'],
              'Second gate: leaves out exactly the confirmed kinds (functions, triggers) and stops on any other; same limit as NC-38 '
              '(no allow-list of known apps).'),
    'NC-49': ('done', {'nextcloud.settings-not-carried': 'notice'},
              [LT + 'test_settings_of_this_devices_postgresql_that_are_refused_are_left_at_their_defaults',
               LT + 'test_settings_that_cannot_be_read_from_this_device_are_a_reminder'], ''),
}


def main(folder):
    rows = {row_id: {'status': status, 'issues': issues, 'tests': tests, 'note': note}
            for row_id, (status, issues, tests, note) in ROWS.items()}
    doc = {'lane': 'NEXTCLOUD', 'rows': rows}
    Path(folder).mkdir(parents=True, exist_ok=True)
    Path(folder, 'ha_parity_rows.json').write_text(json.dumps(doc, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(len(rows), 'rows')


if __name__ == '__main__':
    main(sys.argv[1])
