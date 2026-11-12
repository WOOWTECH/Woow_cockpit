#!/usr/bin/env bash
# Rebuild the cockpit-podman 124 integration from the accompanying source.
set -euo pipefail
task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
task_build=$(mktemp -d)
trap 'rm -rf -- "$task_build"' EXIT
tar -xzf "$task_root/native/podman/source-124.tar.gz" -C "$task_build"
cd "$task_build/cockpit-podman-124"
patch -p1 < "$task_root/native/podman/upstream.patch"
cp "$task_root/native/podman/managed-owners.js" src/managed-owners.js
npm ci --ignore-scripts --no-audit --no-fund
NODE_ENV=production npm run build
cp dist/index.js.gz dist/index.js.LEGAL.txt "$task_root/native/podman/dist/"
