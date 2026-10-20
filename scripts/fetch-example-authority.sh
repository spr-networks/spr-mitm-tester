#!/bin/sh
# Explicitly provision the public G3C OV example supplied by the reporter.
set -eu
config_dir="${1:?usage: fetch-example-authority.sh CONFIG_DIRECTORY [emsign|aaa]}"
issuer="${2:-emsign}"
case "$issuer" in
  emsign)
    source_cert="$(dirname "$0")/../data/certs/em-ov-tls-ca-g3c-emsign.pem"
    expected='CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F'
    ;;
  aaa)
    source_cert="$(dirname "$0")/../data/certs/em-ov-tls-ca-g3c-aaa.pem"
    expected='7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489'
    ;;
  *) echo 'Issuer must be emsign or aaa' >&2; exit 1 ;;
esac
mkdir -p "$config_dir"
umask 077
trap 'rm -f "$config_dir/authority.crt.tmp" "$config_dir/authority.key.tmp" "$config_dir/cert.pub.tmp" "$config_dir/key.pub.tmp"' EXIT
cp "$source_cert" "$config_dir/authority.crt.tmp"
curl -fsSL 'https://gist.githubusercontent.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48/raw/adecc309d3aed74c9590be1a7634b09dfcec1756/private.pem' -o "$config_dir/authority.key.tmp"
fingerprint=$(openssl x509 -in "$config_dir/authority.crt.tmp" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
[ "$fingerprint" = "$expected" ] || {
  echo 'Downloaded certificate fingerprint did not match the affected G3C OV intermediate' >&2
  exit 1
}
openssl x509 -in "$config_dir/authority.crt.tmp" -pubkey -noout > "$config_dir/cert.pub.tmp"
openssl pkey -in "$config_dir/authority.key.tmp" -pubout > "$config_dir/key.pub.tmp"
cmp -s "$config_dir/cert.pub.tmp" "$config_dir/key.pub.tmp" || {
  echo 'Downloaded private key does not match the intermediate' >&2
  exit 1
}
mv "$config_dir/authority.crt.tmp" "$config_dir/authority.crt"
mv "$config_dir/authority.key.tmp" "$config_dir/authority.key"
chmod 600 "$config_dir/authority.crt" "$config_dir/authority.key"
