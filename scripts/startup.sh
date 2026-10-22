#!/bin/sh
set -eu

AUDIT_INTERFACE="${AUDIT_INTERFACE:-eth0}"
export PYTHONPATH="/scripts${PYTHONPATH:+:$PYTHONPATH}"
case "$AUDIT_INTERFACE" in
  *[!a-zA-Z0-9_.:-]*|'') echo "Invalid AUDIT_INTERFACE" >&2; exit 1 ;;
esac
ip link set dev "$AUDIT_INTERFACE" mtu 1400
mkdir -p /state/plugins/spr-mitm-tester /run/mitm-tester
proxy_settings=$(python3 /scripts/configure_upstream_tls.py)
mitm_ssl_option=${proxy_settings%% *}
emudhra_option=${proxy_settings#* }
python3 /scripts/api.py &
api_pid=$!
trap 'kill "$api_pid" 2>/dev/null || true' EXIT INT TERM

# Buildx normalizes image file mtimes to epoch 0. Mitmproxy's script watcher
# only loads a script when its mtime is greater than 0, so stage it in tmpfs.
cp /scripts/probe.py /run/mitm-tester/probe.py

web_token_file=/state/plugins/spr-mitm-tester/mitmweb-token
if [ ! -s "$web_token_file" ]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$web_token_file"
fi
chmod 0600 "$web_token_file"
web_token=$(cat "$web_token_file")
web_gateway=$(ip -4 route show default dev "$AUDIT_INTERFACE" | awk 'NR == 1 { print $3 }')
if [ -z "$web_gateway" ]; then
  echo "No host gateway on $AUDIT_INTERFACE for the mitmweb access rule" >&2
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
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "$AUDIT_INTERFACE" tcp dport 8081 ip saddr "$web_gateway" accept
    iifname "$AUDIT_INTERFACE" tcp dport 8081 drop
  }
}
EOF

mitmweb --mode transparent --listen-host 0.0.0.0 --listen-port 9999 \
  "$emudhra_option" \
  --set web_host=0.0.0.0 --set web_port=8081 --set web_open_browser=false \
  --set "web_password=$web_token" \
  --set confdir=/run/mitm-tester --set connection_strategy=eager \
  --set "$mitm_ssl_option" \
  --set ssl_verify_upstream_trusted_ca=/scripts/upstream-trust.pem \
  --set stream_large_bodies=1 -s /run/mitm-tester/probe.py
