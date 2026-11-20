# Joined synthetic HA to EMQX adapter evidence

JSONL files retain each attempted run, its source commit, image IDs, named stages,
and cleanup outcomes. Independent cleanup lines record separate labpodman queries.

The `0009c8c` run failed at `candidate_target_marker`: the test had incorrectly
required the target's prior retained business data to survive. The converter's
documented contract says retained messages are replaced by HA data; its target
snapshot carries referenced configuration files, not target Mnesia. The updated
test checks that the target-only marker is absent after installation, the HA-only
marker and HA-only MQTT user are present, and a marker created after installation
is recovered after the deliberately failed second restore. ACL and effective
target settings remain separate preservation checks. No public guard is changed.
