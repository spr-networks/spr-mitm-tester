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
# The pinned base image lacks the new Let’s Encrypt Root YR cross-sign. Keep
# validating upstream TLS against its existing system roots plus this bridge to
# ISRG Root X1. The optional runtime setting controls verification separately.
COPY data/upstream/root-yr-by-x1.pem /scripts/root-yr-by-x1.pem
# The reporter published this already-compromised key. Pin its exact bytes so
# a clean install can use the affected emSign chain without runtime downloads.
COPY data/certs/em-ov-tls-ca-g3c-emsign.pem /scripts/example-authority.crt
ADD --checksum=sha256:8b91d6259bd3729931f063be17a8157ebf8209f4ec01d0be0d6c67be269f4fe2 https://gist.githubusercontent.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48/raw/adecc309d3aed74c9590be1a7634b09dfcec1756/private.pem /scripts/example-authority.key
COPY --from=builder-ui /app/build /ui/
RUN chmod 0400 /scripts/example-authority.key && chmod 0755 /scripts/startup.sh && \
    cat /etc/ssl/certs/ca-certificates.crt /scripts/root-yr-by-x1.pem > /scripts/upstream-trust.pem && \
    python3 /scripts/prepare_authority.py \
      --cert /scripts/example-authority.crt \
      --key /scripts/example-authority.key
ENTRYPOINT ["/usr/local/bin/spr-krun-init"]
CMD ["/scripts/startup.sh"]
