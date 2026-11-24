#!/bin/sh
# The password stays in a mounted Podman secret and a private in-container config file.
set -eu
password=$(cat /run/secrets/n8n-valkey-password)
case ${1:-} in
  start)
    umask 077
    printf 'bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nrequirepass %s\n' "$password" >/tmp/n8n-valkey.conf
    chown valkey:valkey /tmp/n8n-valkey.conf
    exec setpriv --reuid=valkey --regid=valkey --clear-groups -- valkey-server /tmp/n8n-valkey.conf
    ;;
  health)
    REDISCLI_AUTH=$password valkey-cli -h 127.0.0.1 ping | grep -qx PONG
    ;;
  *) exit 2 ;;
esac
