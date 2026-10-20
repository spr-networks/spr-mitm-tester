ARG MITMPROXY_REF=mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f
ARG SPR_KRUN_PLUGIN_REF=ghcr.io/spr-networks/spr-krun-plugin@sha256:fbb21da9c52abeb609a487e55e4f6b893e656d0434f62f405647c79057a9cfa9
ARG NODE_REF=node:18@sha256:c6ae79e38498325db67193d391e6ec1d224d96c693a8a4d943498556716d3783

FROM ${SPR_KRUN_PLUGIN_REF} AS krun-plugin
FROM ${NODE_REF} AS builder-ui
WORKDIR /app
COPY frontend/ ./
RUN yarn install --frozen-lockfile --network-timeout 86400000 && yarn run bundle

FROM ${MITMPROXY_REF}
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=krun-plugin /usr/local/bin/spr-krun-init /usr/local/bin/
COPY --from=krun-plugin /usr/local/bin/spr-krun-vsock-proxy /usr/local/bin/
COPY scripts/ /scripts/
COPY data/affected-tls.json /scripts/affected-tls.json
COPY data/roots/ /scripts/roots/
COPY --from=builder-ui /app/build /ui/
RUN chmod 0755 /scripts/startup.sh
ENTRYPOINT ["/usr/local/bin/spr-krun-init"]
CMD ["/scripts/startup.sh"]
