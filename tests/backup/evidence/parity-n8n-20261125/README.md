# Evidence of lane N8N (HAOS parity, 15 rows) -- unit level, nothing run on a device
Branch parity/n8n-20261125 (start 47c6cfd = parity-int/combined-20261125). Product file: backup-engine/woowbackup/ha_n8n.py. commercial_acceptance: not-complete.

## What was simulated, what was real
- Simulated (hab1fakes / hafakes): podman and everything in a container (the throwaway n8n, PostgreSQL, `pg_dump`, `pg_controldata`, volume export/import), the
  owner's runner, the image pulls, the user manager. The conversion's own logic (Target, analyse, convert, carry, the confirmation keys) is the real code.
- Real: the SQLite child (`python3 -I -S`, real SQLite files, the retry with a killed / timed-out / failing child as real processes), the HA backup readers
  (habackup), the issue model (haissues), the registry of imports (haimport), the tar writers. The child runs as the unprivileged test user: the root-only set-up
  (unshare, chroot, setuid) is not exercised here (arm54_final_n8n_sandbox_probe.py did that on .54 for the unchanged lines).
- Real data: tests/backup/fixtures/reference-host (the real Quadlet files of the reference host, names and mounts only) fill Target in both layouts.

## Results (filled when the final tip was frozen; see the lane file for the date)
RESULTS BELOW WHEN FINISHED

## Security notes (DESIGN H-c "security re-review" for what this lane touched)
- Credential names are read by the sandboxed child (names only, <= 20000, each cut at 200 characters), shown through haissues (control and bidirectional
  characters replaced, 120 characters, 20 names; the confirmation key covers all names). No credential value is read, and none is logged.
- The key (HA's or the new one) stays masked (jobs.mask_secret; not for a text shorter than 4 characters), is only written into JSON files in throwaway and
  final volumes (json.dumps: any text is safe there), never into an argument, a message, a log, a result or a registry row (tests assert it).
- Limits: the first SQLite run has the limits it always had (2 GiB address space; time = 1800 s + 1 s per 20 MiB, never less than before); only a run that
  failed is repeated with twice the time and memory (ceiling 8 GiB, a day). The row and total caps of the workflows' JSON are unchanged (so is what the child
  can hold in memory).
- Big files: the reader (habackup) is unchanged: names, links, devices, member and byte limits all apply; only the per-file stops of N8-28 are gone, and the bytes
  of a streamed file are counted by the job's space guard while they are written (a full disk still stops the job).
- Cold mode: the podman secret of this device's database password is handed to throwaway containers by NAME (type=env / a file secret), the containers have no
  network but their own internal one; the new cluster's password is that password, so the exported volume holds its hash like the live cluster does (the
  converted backup is encrypted by default like every converted backup).
