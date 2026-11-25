"""Builds snippets/parity-hh/ha_parity_rows.json (the lane HERMES-HEADSCALE rows) for the integrator's merge tool."""
import json
import sys

H = 'tests/backup/test_ha_hermes.py::'
S = 'tests/backup/test_ha_headscale.py::'
rows = {}


def row(row_id, status, issues, tests, note=''):
    rows[row_id] = {'status': status, 'issues': issues, 'tests': tests, 'note': note}


# ---- Hermes
row('H-01', 'done', {'hermes.links-copied': 'auto', 'files.skipped': 'confirm'},
    [H + 'LinkTests.test_a_hard_link_to_a_runtime_file_is_copied_as_a_file',
     H + 'LinkTests.test_a_hard_link_to_a_file_that_may_never_be_copied_is_left_out_and_listed',
     H + 'LinkTests.test_one_more_hard_link_that_stays_out_is_another_line_to_confirm',
     H + 'LinkTests.test_the_check_and_the_conversion_judge_a_link_the_same_way'],
    'copy = hacommon.TreeTar.hardlink(entry=...); a link to something the reader may never copy (a browser profile) is left out and listed (files.skipped)')
row('H-03', 'part', {'hermes.extras-carried': 'auto', 'hermes.layout-unsupported': 'stop'},
    [H + 'LayoutTests.test_a_cold_entry_and_a_folder_are_carried_as_they_are',
     H + 'LayoutTests.test_an_entry_that_dumps_a_whole_instance_stops_only_hermes',
     H + 'LayoutTests.test_two_database_entries_are_both_dumped',
     H + 'LayoutTests.test_a_redis_volume_that_is_not_there_is_no_reason_to_stop'],
    'cold entries, extra volumes/folders, several database entries done; an entry that dumps a whole PostgreSQL INSTANCE still stops only Hermes: adapter.import_manifest (adapters/quadlet_postgres.py, RESTORE lane) takes one dump file per entry')
row('H-05', 'done', {'hermes.owner-from-folder': 'auto'},
    [H + 'LayoutTests.test_an_owner_the_settings_do_not_say_is_the_live_folders',
     H + 'LayoutTests.test_an_owner_that_cannot_be_read_stops_only_hermes'])
row('H-02', 'done', {'hermes.entries-skipped': 'confirm', 'hermes.databases-skipped': 'confirm', 'hermes.state-db-unusable': 'stop'},
    [H + 'EntryTests.test_every_special_file_that_is_a_link_is_left_out_and_listed',
     H + 'EntryTests.test_one_more_entry_is_another_line_to_confirm',
     H + 'DatabaseTests.test_a_secondary_database_whose_wal_is_a_link_stays_out_whole',
     H + 'DatabaseTests.test_a_main_database_that_stands_where_a_link_is_stops_only_hermes',
     H + 'EntryTests.test_a_folder_where_a_file_must_be_goes_with_what_lies_below_it'])
row('H-10', 'done', {'hermes.no-state-db': 'stop'}, [H + 'DatabaseTests.test_a_backup_without_state_db_stops_only_hermes'])
row('H-11', 'done', {'hermes.databases-skipped': 'confirm', 'hermes.state-db-unusable': 'stop', 'hermes.db-unchecked': 'notice'},
    [H + 'DatabaseTests.test_a_damaged_secondary_database_is_left_out_with_its_wal',
     H + 'DatabaseTests.test_a_damaged_main_database_stops_only_hermes',
     H + 'DatabaseTests.test_an_index_structure_the_sandbox_does_not_know_moves_unchecked',
     H + 'DatabaseTests.test_the_other_parts_of_a_damaged_group_do_not_reach_the_sandbox'])
row('H-06', 'done', {'version.addon-unknown': 'notice'}, [H + 'VersionTests.test_an_addon_version_the_table_does_not_know_is_a_notice_and_the_data_moves'])
row('H-07', 'done', {'version.target-unknown': 'notice'},
    [H + 'VersionTests.test_a_version_of_this_device_that_cannot_be_read_is_a_notice_and_the_data_moves'])
row('H-09', 'done', {'hermes.image-version-differs': 'notice'},
    [H + 'VersionTests.test_a_version_record_that_differs_from_the_addon_is_a_notice_and_the_data_moves'])
row('H-15', 'done', {}, [H + 'EntryTests.test_an_env_that_is_a_link_is_no_refusal'])
row('H-18', 'done', {}, [H + 'SizeTests.test_a_version_record_over_one_kib_is_read_at_its_start_only'])
row('H-19', 'done', {},
    [H + 'SizeTests.test_an_env_over_the_old_limit_moves_filtered', H + 'SizeTests.test_an_env_too_large_to_filter_is_left_out_and_listed',
     H + 'SizeTests.test_a_hostile_env_registers_a_bounded_number_of_secrets', H + 'CheckTests.test_a_backup_that_does_not_fit_stops_only_hermes'],
    'the limit is 8 MiB now (filtered in memory); a larger .env is left out and listed (files.skipped), never moved unfiltered')
row('H-20', 'done', {'hermes.text-unread': 'notice'},
    [H + 'SizeTests.test_a_settings_file_and_a_job_list_over_the_old_limit_move_and_are_read',
     H + 'SizeTests.test_a_text_file_larger_than_what_is_read_is_copied_unread'])
row('H-21', 'done', {'hermes.text-unread': 'notice'},
    [H + 'SizeTests.test_a_skill_over_the_old_limit_is_copied', H + 'SizeTests.test_a_text_file_larger_than_what_is_read_is_copied_unread'])
row('H-14', 'done', {'hermes.config-newer': 'notice'}, [H + 'VersionTests.test_a_newer_settings_file_is_a_notice_and_moves_as_it_is'])
row('H-16', 'done', {'hermes.foreign-programs': 'notice'}, [H + 'CheckTests.test_programs_for_another_processor_are_listed_and_move'])

# ---- Headscale
row('HS-03', 'done', {'headscale.layout-unsupported': 'stop'},
    [S + 'LayoutTests.test_the_server_is_found_by_what_it_mounts', S + 'LayoutTests.test_a_setup_without_a_server_container_stops_only_headscale'])
row('HS-04', 'done', {'headscale.headplane-absent': 'auto', 'headscale.extras-carried': 'auto', 'headscale.layout-unsupported': 'stop'},
    [S + 'LayoutTests.test_without_headplane_only_headscale_moves', S + 'LayoutTests.test_other_volumes_and_folders_are_carried_as_they_are',
     S + 'LayoutTests.test_an_entry_with_a_database_export_stops_only_headscale', S + 'ConfigFolderTests.test_any_other_folder_is_carried_as_it_is'])
row('HS-06', 'done', {'headscale.config-link-followed': 'auto', 'headscale.config-unreadable': 'stop'},
    [S + 'LayoutTests.test_a_config_that_is_a_link_into_the_home_folder_is_read',
     S + 'LayoutTests.test_a_config_that_is_a_link_out_of_the_home_folder_or_missing_stops_only_headscale',
     S + 'LayoutTests.test_a_config_larger_than_one_mib_is_read'],
    'a link is followed once and only into the owner home folder (podman unshare readlink, simulated here); never run against a real podman')
row('HS-22', 'done', {'headscale.prefixes-replaced': 'confirm', 'headscale.prefixes-kept': 'notice', 'headscale.config-edit-failed': 'stop'},
    [S + 'PrefixTests.test_the_prefixes_become_has_in_the_converted_folder',
     S + 'PrefixTests.test_not_confirmed_stops_only_headscale_and_one_more_range_needs_the_confirmation_again',
     S + 'PrefixTests.test_without_the_folder_the_range_stays_and_the_devices_outside_it_are_listed',
     S + 'PrefixTests.test_an_unchanged_range_is_not_touched', S + 'PrefixTests.test_a_config_whose_range_cannot_be_written_stops_only_headscale',
     S + 'EditTests.test_only_the_value_changes'],
    'configtest then reads the converted folder from a throwaway volume (not run against a real podman: R7 confirms)')
row('HS-24', 'done', {'headscale.policy-unreadable': 'stop', 'headscale.live-copy-unreadable': 'stop'},
    [S + 'LiveCopyTests.test_a_torn_copy_is_read_again_in_the_check', S + 'LiveCopyTests.test_a_copy_that_stays_unreadable_stops_only_headscale',
     S + 'PolicyTests.test_a_policy_that_cannot_be_read_stops_only_headscale'])
row('HS-26', 'done', {'headscale.live-copy-unreadable': 'stop'},
    [S + 'LiveCopyTests.test_an_export_that_is_no_tar_is_read_again', S + 'LiveCopyTests.test_a_copy_that_stays_unreadable_stops_only_headscale'])
row('HS-27', 'done', {'headscale.live-db-missing': 'stop', 'target.service-started': 'auto'},
    [S + 'LiveCopyTests.test_a_headscale_that_never_ran_is_started_once_and_put_back',
     S + 'LiveCopyTests.test_a_headscale_that_makes_no_database_stops_only_headscale',
     S + 'LiveCopyTests.test_a_running_headscale_without_a_database_is_not_waited_for'])
row('HS-29', 'done', {'headscale.live-copy-unreadable': 'stop'},
    [S + 'LiveCopyTests.test_a_torn_copy_is_read_again_in_the_conversion', S + 'ConvertTests.test_a_damaged_live_copy_stops_the_conversion'])
row('HS-36', 'done', {'headscale.config-changed': 'stop'},
    [S + 'ConfigChangeTests.test_a_config_that_changed_while_it_was_packed_is_packed_again',
     S + 'ConfigChangeTests.test_a_config_that_keeps_changing_stops_only_headscale'])
row('HS-13', 'done', {'headscale.no-database': 'stop'},
    [S + 'DatabaseTests.test_a_backup_without_a_database_stops_only_headscale', S + 'DatabaseTests.test_a_database_that_is_only_the_header_page_is_no_database'])
row('HS-15', 'part', {'headscale.db-extra-objects': 'stop'},
    [S + 'DatabaseTests.test_this_devices_own_tables_are_not_extra_ones', S + 'CheckTests.test_what_makes_the_data_unusable_stops_only_headscale'],
    "the comparison base is this device's own tables now; REMOVING extra tables, triggers and views from HA's copy needs a write operation in the SQLite child (hasqlite.py, N8N lane's file): until then such a database stops only Headscale")
row('HS-23', 'done', {'headscale.dns-records-invalid': 'confirm'},
    [S + 'DnsRecordTests.test_an_invalid_file_is_left_out_and_listed', S + 'DnsRecordTests.test_one_more_confirmation_is_needed_for_another_line',
     S + 'IdentityKeyTests.test_the_confirmation_of_another_line_is_no_confirmation_of_this_one'])
row('HS-28', 'done', {'headscale.no-database': 'stop'}, [S + 'DatabaseTests.test_a_backup_without_a_database_stops_only_headscale'])
row('HS-34', 'done', {'headscale.dns-path-conflict': 'confirm'},
    [S + 'DnsRecordTests.test_a_dns_path_that_would_overwrite_the_database_is_not_written_and_listed',
     S + 'DnsRecordTests.test_a_dns_path_conflict_is_one_line_with_its_own_key',
     S + 'IdentityKeyTests.test_the_confirmation_of_another_line_is_no_confirmation_of_this_one'])
row('HS-02', 'done', {}, [S + 'DatabaseTests.test_a_database_larger_than_the_old_limit_is_no_refusal',
                          S + 'DatabaseTests.test_this_devices_database_larger_than_the_old_limit_is_no_refusal',
                          S + 'DatabaseTests.test_a_backup_that_does_not_fit_stops_only_headscale'],
    'no size limit: the job watchdog watches the free space; tested with a 5 GiB entry that only claims its size')
row('HS-08', 'done', {}, [S + 'LayoutTests.test_a_path_with_spaces_or_other_letters_is_no_error',
                          S + 'LayoutTests.test_a_path_that_leaves_the_data_volume_still_stops_only_headscale'])
row('HS-10', 'done', {'version.addon-unknown': 'notice'}, [S + 'VersionTests.test_an_addon_version_the_table_does_not_know_is_a_notice_and_the_data_moves'])
row('HS-11', 'done', {'version.target-unknown': 'notice'},
    [S + 'VersionTests.test_a_version_of_this_device_that_cannot_be_read_is_a_notice_and_the_data_moves'])
row('HS-16', 'done', {'headscale.db-version-differs': 'notice'},
    [S + 'VersionTests.test_a_database_of_another_version_is_a_notice_and_configtest_decides',
     S + 'VersionTests.test_a_database_this_devices_headscale_cannot_open_stops_only_headscale'])
row('HS-17', 'done', {}, [S + 'VersionTests.test_a_release_without_a_list_of_migrations_is_no_reason_to_stop'])
row('HS-18', 'done', {'headscale.db-version-differs': 'notice'},
    [S + 'VersionTests.test_migrations_this_release_does_not_know_are_a_notice_and_configtest_decides'])
row('HS-21', 'done', {'headscale.prefixes-unknown': 'notice'},
    [S + 'PrefixTests.test_a_range_that_cannot_be_read_is_no_refusal', S + 'PrefixTests.test_an_installation_with_ipv4_only_is_no_error'])
row('HS-39', 'done', {}, [S + 'DnsRecordTests.test_a_valid_file_over_the_old_limit_moves', S + 'DnsRecordTests.test_a_file_larger_than_any_valid_one_is_not_read_and_listed'])
row('HS-40', 'done', {'headscale.prefixes-unknown': 'notice'},
    [S + 'DnsRecordTests.test_a_settings_file_over_the_old_limit_is_read', S + 'DnsRecordTests.test_a_settings_file_larger_than_any_valid_one_is_no_refusal'])
row('HS-19', 'done', {'headscale.devices-outside-range': 'confirm'},
    [S + 'PrefixTests.test_devices_outside_the_range_are_one_line_to_confirm',
     S + 'PrefixTests.test_a_device_outside_the_range_moves_with_the_others_after_the_confirmation',
     S + 'PrefixTests.test_without_the_folder_the_range_stays_and_the_devices_outside_it_are_listed'])
row('HS-20', 'done', {'headscale.noise-key-kept': 'confirm'},
    [S + 'IdentityKeyTests.test_without_a_key_the_line_is_to_confirm_and_nothing_is_made_without_it',
     S + 'IdentityKeyTests.test_confirmed_this_devices_key_moves_and_not_has',
     S + 'IdentityKeyTests.test_the_confirmation_of_another_line_is_no_confirmation_of_this_one',
     S + 'IdentityKeyTests.test_a_device_that_has_no_key_either_gets_a_new_one_from_headscale'])
row('HS-38', 'done', {'headscale.noise-key-kept': 'confirm'},
    [S + 'IdentityKeyTests.test_a_key_longer_than_a_key_is_the_same_line',
     S + 'IdentityKeyTests.test_without_a_key_the_line_is_to_confirm_and_nothing_is_made_without_it',
     S + 'IdentityKeyTests.test_confirmed_this_devices_key_moves_and_not_has'])
policy_tests = [S + 'PolicyTests.test_ha_policy_in_its_database_replaces_this_devices_after_the_confirmation',
                S + 'PolicyTests.test_when_ha_has_none_this_devices_stays_in_the_converted_database',
                S + 'PolicyTests.test_a_policy_of_this_device_that_cannot_be_kept_stops_only_headscale',
                S + 'PolicyTests.test_a_device_with_a_policy_file_keeps_it',
                S + 'PolicyTests.test_ha_policy_file_is_said_not_to_be_applied',
                S + 'PolicyTests.test_a_policy_ha_does_not_use_must_not_apply_here',
                S + 'RealChildPolicyTests.test_the_real_child_puts_this_devices_policy_into_the_converted_database']
policy_issues = {'headscale.policy-replaced': 'confirm', 'headscale.policy-kept': 'notice', 'headscale.policy-not-applied': 'confirm',
                 'headscale.policy-stale': 'confirm', 'headscale.policy-keep-unsupported': 'stop'}
row('HS-25', 'part', policy_issues, policy_tests,
    'S3: HA replaces / none from HA: this device stays -- done; keeping a policy that lives in this device DATABASE needs the SQLite child op replace_policies_from (snippet hasqlite.py.patch, tested with it): until it is in the tree that case stops only Headscale (policy-keep-unsupported); HA policy FILES are not applied (said in a confirm line)')
row('HS-30', 'part', policy_issues, policy_tests, 'the same check again in the conversion (Sink); see HS-25 for the part that waits for the child op')

doc = {'lane': 'HERMES-HEADSCALE', 'rows': rows}
out = sys.argv[1]
with open(out, 'w', encoding='utf-8') as handle:
    handle.write(json.dumps(doc, ensure_ascii=False, indent=1) + '\n')
print(len(rows), 'rows ->', out)
