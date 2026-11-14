# Reference-host Quadlet fixture (catalog-suggest tests)

`quadlet/` holds 90 Quadlet files in the shapes of the apps on the reference host (2026-11-13): LiteLLM, n8n in queue
mode with task runners, Hermes, EMQX with its entrance in the broker's network namespace, OpenDesign, the Headscale group,
Odoo 18 (cold database, addons directory), Nextcloud with four host directories, Home Assistant (host network, config
directory), ten `*-mcp-admin` containers and code-server with `~/.ssh`, `~/Desktop` and `~/.gitconfig` binds.

They carry names, mounts, ports and dependencies only: no secret value, no environment file content (the files listed in
`home.json` hold a placeholder and are never read by `catalog-suggest`), invented image names, and the LAN address the
reference host binds EMQX to replaced by a documentation address (192.0.2.10). `tests/backup/test_suggest.py` builds a
temporary home from `home.json` (bind-mount sources and environment files with their modes), copies the Quadlet files
into `~/.config/containers/systemd/` and compares the drafts with the structural facts of the hand-written production
catalog entries.
