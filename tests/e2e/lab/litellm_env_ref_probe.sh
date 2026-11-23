#!/bin/sh
# SR-7 probe (LiteLLM HA import security review, iteration 2): runs litellm_env_ref_probe.py in a throwaway
# --network=none container of the package's LiteLLM lab build (0c71bec8, already in dev-d's appowner store) inside
# dev-d, under the dev-d mutation lock; the container is removed before the lock is released; dev-d's isolation is
# asserted afterwards. Usage: tests/e2e/lab/litellm_env_ref_probe.sh <out.json>
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$1
LP=$HOME/.woowbk-lab/bin/labpodman
IMG=sha256:0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312
RUN="timeout 900 podman run --rm -i --name woowbk-review-sr7 --network=none --read-only --tmpfs /tmp:rw,size=256m \
--memory 1200m --pids-limit 256 --cap-drop=ALL --security-opt=no-new-privileges -e HOME=/tmp \
-e LITELLM_LOCAL_MODEL_COST_MAP=True --entrypoint /app/.venv/bin/python $IMG -I -; rc=\$?; \
podman rm -f woowbk-review-sr7 >/dev/null 2>&1; podman ps -a --filter name=woowbk-review-sr7 --format x | wc -l; exit \$rc"
flock -w 3600 /tmp/woowbk-dev-d-mutation.lock sh -c "
  start=\$(date +%s)
  \"$LP\" exec -i woowbk-dev-d su - appowner -c '$RUN' < \"$HERE/litellm_env_ref_probe.py\" > \"$OUT.raw\" 2> \"$OUT.err\"; rc=\$?
  echo \"rc=\$rc seconds=\$((\$(date +%s) - start))\" >> \"$OUT.err\"
  \"$HERE/owner.sh\" d --verify-isolation >> \"$OUT.err\" 2>&1 || echo 'isolation check FAILED' >> \"$OUT.err\"
"
