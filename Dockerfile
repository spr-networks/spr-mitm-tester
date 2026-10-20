# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
ARG NODE_REF=node:18@sha256:c6ae79e38498325db67193d391e6ec1d224d96c693a8a4d943498556716d3783
ARG MITMPROXY_REF=mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f
ARG SPR_KRUN_PLUGIN_REF=ghcr.io/spr-networks/spr-krun-plugin@sha256:fbb21da9c52abeb609a487e55e4f6b893e656d0434f62f405647c79057a9cfa9
ARG SOURCE_DATE_EPOCH=0

FROM ${SPR_KRUN_PLUGIN_REF} AS krun-plugin

FROM ${NODE_REF} AS builder-ui
WORKDIR /app
COPY frontend/ ./
ARG SOURCE_DATE_EPOCH
ENV CI=true SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} TZ=UTC
RUN --mount=type=tmpfs,target=/root/.cache \
    --mount=type=tmpfs,target=/app/node_modules \
    yarn install --frozen-lockfile --non-interactive --network-timeout 86400000 && yarn run bundle

FROM ${MITMPROXY_REF}
ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
ARG DEBIAN_SNAPSHOT=20260505T000000Z
RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n\nTypes: deb\nURIs: https://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n' "${DEBIAN_SNAPSHOT}" "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/debian.sources; \
    printf 'APT::Install-Recommends "false";\nAcquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99reproducible; \
    apt-get update; \
    apt-get install -y --no-install-recommends nftables iproute2; \
    rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
COPY --from=krun-plugin /usr/local/bin/spr-krun-init /usr/local/bin/
COPY --from=krun-plugin /usr/local/bin/spr-krun-vsock-proxy /usr/local/bin/
COPY scripts/ /scripts/
COPY data/affected-tls.json /scripts/affected-tls.json
COPY data/roots/ /scripts/roots/
COPY --from=builder-ui /app/build /ui/
RUN chmod 0755 /scripts/startup.sh
ENTRYPOINT ["/usr/local/bin/spr-krun-init"]
CMD ["/scripts/startup.sh"]
