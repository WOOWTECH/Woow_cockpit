# localhost/woow-headscale:<headscale version>-r<package revision>
#
# Built by scripts/install.sh and scripts/upgrade.sh; there is no registry image for it
# (decision D3 - publishing to GHCR is future work, see README "Image and versions").
# Bump the tag in quadlet/headscale.container and HEADSCALE_IMAGE in scripts/common.sh
# together, then run scripts/upgrade.sh.
#
# Why a build at all, when upstream publishes a perfectly good image: the upstream image is
# built with ko and contains the headscale binary and nothing else - no shell, no coreutils.
# A Quadlet HealthCmd= becomes `podman run --health-cmd`, and podman runs a non-JSON value
# through /bin/sh, so the health check could not run there. Adding a Debian base keeps the
# unmodified upstream binary and gives the health check a shell to live in.
#
# Both bases are pinned by digest, so a rebuild on another host produces the same runtime.
ARG HEADSCALE_SOURCE=ghcr.io/juanfont/headscale:v0.29.4@sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f
FROM ${HEADSCALE_SOURCE} AS upstream

FROM docker.io/library/debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef
COPY --from=upstream /ko-app/headscale /ko-app/headscale
COPY --from=upstream /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

LABEL org.opencontainers.image.title="Woow Headscale runtime" \
      org.opencontainers.image.version="0.29.4" \
      org.opencontainers.image.source="https://github.com/WOOWTECH/Woow_podman_vpn_headscale_package" \
      io.woowtech.app="headscale" \
      io.woowtech.headscale.source-image="ghcr.io/juanfont/headscale:v0.29.4@sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f"

# /ko-app on PATH so `podman exec headscale headscale ...` works without a full path.
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/ko-app" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    KO_DATA_PATH="/var/run/ko"
WORKDIR /
ENTRYPOINT ["/ko-app/headscale"]
