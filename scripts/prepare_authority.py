#!/usr/bin/env python3
"""Validate an affected TLS intermediate/key pair for mitmproxy's CA store."""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


ROOT_FILES = {
    "emSign Root TLS CA - G3": "emsign-root-tls-g3.pem",
    "AAA Certificate Services": "aaa-certificate-services.pem",
}


def prepare(
    cert_path: Path,
    key_path: Path,
    catalogue_path: Path,
    roots_dir: Path,
    output_dir: Path | None,
):
    catalogue = json.loads(catalogue_path.read_text())
    allowed = {row["sha256"]: row for row in catalogue["certificates"]}
    cert_bytes = cert_path.read_bytes()
    key_bytes = key_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes)
    key = serialization.load_pem_private_key(key_bytes, password=None)

    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    row = allowed.get(fingerprint)
    if row is None:
        raise ValueError("certificate is not one of the 12 listed eMudhra TLS intermediates")
    public = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if public != key_public:
        raise ValueError("private key does not match the affected intermediate")
    if hashlib.sha256(public).hexdigest().upper() != row["spki_sha256"]:
        raise ValueError("catalogue SPKI mismatch")
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("certificate is not a CA")
    if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
        raise ValueError("certificate cannot sign certificates")
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("certificate is outside its validity period")

    root_file = ROOT_FILES.get(row["issued_by"])
    if root_file is None:
        raise ValueError("unsupported issuer")
    root = x509.load_pem_x509_certificate((roots_dir / root_file).read_bytes())
    if root.fingerprint(hashes.SHA256()).hex().upper() != row["issuer_sha256"]:
        raise ValueError("issuer root fingerprint mismatch")
    if cert.issuer != root.subject:
        raise ValueError("intermediate issuer does not match the selected root")
    root_public = root.public_key()
    if isinstance(root_public, ec.EllipticCurvePublicKey):
        root_public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    elif isinstance(root_public, rsa.RSAPublicKey):
        root_public.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        raise ValueError("unsupported issuer key type")

    authority = {
        "name": row["name"],
        "issued_by": row["issued_by"],
        "sha256": fingerprint,
        "spki_sha256": row["spki_sha256"],
    }
    if output_dir is not None:
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ) + cert.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM)
        ca_path = output_dir / "mitmproxy-ca.pem"
        fd = os.open(ca_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(pem)
        (output_dir / "authority.json").write_text(json.dumps(authority))
    return authority


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--catalogue", type=Path, default=Path("/scripts/affected-tls.json"))
    parser.add_argument("--roots-dir", type=Path, default=Path("/scripts/roots"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.cert, args.key, args.catalogue, args.roots_dir, args.output)))
