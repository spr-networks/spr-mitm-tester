#!/usr/bin/env bash
# Resolve new upstream digests deliberately; review the diff before committing.
set -euo pipefail
cd "$(dirname "$0")"

digest() { docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}'; }
node_ref="node:18@$(digest node:18)"
syntax_ref="docker/dockerfile:1@$(digest docker/dockerfile:1)"
buildkit_ref="moby/buildkit:buildx-stable-1@$(digest moby/buildkit:buildx-stable-1)"
mitmproxy_ref="mitmproxy/mitmproxy@$(digest mitmproxy/mitmproxy:latest)"
krun_ref="ghcr.io/spr-networks/spr-krun-plugin@$(digest ghcr.io/spr-networks/spr-krun-plugin:latest)"
snapshot="${DEBIAN_SNAPSHOT:-$(sed -n 's/^DEBIAN_SNAPSHOT=//p' reproducible.env)}"

for suite in "debian/${snapshot}/dists/trixie/InRelease" "debian-security/${snapshot}/dists/trixie-security/InRelease"; do
  curl -LfsS -o /dev/null "https://snapshot.debian.org/archive/${suite}"
done

cat > reproducible.env <<EOF
# Pinned build inputs for build_docker_compose.sh and CI. Update deliberately and review the resulting diff.
NODE_REF=${node_ref}
DOCKERFILE_SYNTAX=${syntax_ref}
BUILDKIT_REF=${buildkit_ref}
MITMPROXY_REF=${mitmproxy_ref}
SPR_KRUN_PLUGIN_REF=${krun_ref}
DEBIAN_SNAPSHOT=${snapshot}
EOF

python3 - <<'PY'
from pathlib import Path

values = dict(line.split("=", 1) for line in Path("reproducible.env").read_text().splitlines() if line and not line.startswith("#"))
dockerfile = Path("Dockerfile")
lines = dockerfile.read_text().splitlines()
for index, line in enumerate(lines):
    if line.startswith("# syntax="):
        lines[index] = "# syntax=" + values["DOCKERFILE_SYNTAX"]
    elif line.startswith("ARG "):
        name = line[4:].split("=", 1)[0]
        if name in values:
            lines[index] = f"ARG {name}={values[name]}"
dockerfile.write_text("\n".join(lines) + "\n")
PY

echo 'Pins updated; review with git diff' >&2
