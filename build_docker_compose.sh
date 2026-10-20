#!/usr/bin/env bash
# Pinned BuildKit inputs and normalized image timestamps, following spr-mitmproxy.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./reproducible.env
set +a
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

find . \( -name .git -o -name node_modules -o -name build -o -name __pycache__ \) -prune -o -exec chmod go-w {} +

bake_set=()
while IFS='=' read -r key value; do
  case "$key" in
    NODE_REF|MITMPROXY_REF|SPR_KRUN_PLUGIN_REF|DEBIAN_SNAPSHOT)
      bake_set+=(--set "*.args.${key}=${value}")
      ;;
  esac
done < reproducible.env
bake_set+=(--set "*.args.SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}")

builder=spr-mitm-tester-builder
if docker buildx inspect "$builder" >/dev/null 2>&1; then
  current=$(docker buildx inspect "$builder" | sed -n 's/.*image="\([^"]*\)".*/\1/p' | head -1)
  if [ "$current" != "$BUILDKIT_REF" ]; then
    echo "Existing $builder uses a different BuildKit image; remove it before building" >&2
    exit 1
  fi
else
  docker buildx create --name "$builder" --driver docker-container --driver-opt "image=$BUILDKIT_REF" >/dev/null
fi

output=type=docker,rewrite-timestamp=true
args=()
for arg in "$@"; do
  case "$arg" in
    --load) ;;
    --push) output=type=registry,rewrite-timestamp=true ;;
    *) args+=("$arg") ;;
  esac
done

docker buildx bake --builder "$builder" --file docker-compose.yml \
  "${bake_set[@]}" --set "*.output=${output}" ${args[@]+"${args[@]}"}
