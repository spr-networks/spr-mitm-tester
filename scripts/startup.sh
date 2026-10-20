#!/bin/sh
set -eu

AUDIT_INTERFACE="${AUDIT_INTERFACE:-eth0}"
case "$AUDIT_INTERFACE" in
  *[!a-zA-Z0-9_.:-]*|'') echo "Invalid AUDIT_INTERFACE" >&2; exit 1 ;;
esac
ip link set dev "$AUDIT_INTERFACE" mtu 1400
mkdir -p /state/plugins/spr-mitm-tester /run/mitm-tester
python3 /scripts/api.py &
api_pid=$!
trap 'kill "$api_pid" 2>/dev/null || true' EXIT INT TERM

if ! python3 /scripts/prepare_authority.py \
  --cert /configs/spr-mitm-tester/authority.crt \
  --key /configs/spr-mitm-tester/authority.key \
  --output /run/mitm-tester; then
  echo "No validated eMudhra TLS authority. Plugin API remains available; interception is disabled." >&2
  wait "$api_pid"
  exit 1
fi

nft -f - <<EOF
table inet mitm_tester {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$AUDIT_INTERFACE" tcp dport 443 redirect to :9999
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "$AUDIT_INTERFACE" drop
  }
}
EOF

mitmdump -q --mode transparent --listen-host 0.0.0.0 --listen-port 9999 \
  --set confdir=/run/mitm-tester --set connection_strategy=eager \
  --set stream_large_bodies=1 -s /scripts/probe.py
