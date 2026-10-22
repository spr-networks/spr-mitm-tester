"""Describe the affected authority bundled with the pinned mitmproxy image.

Certificate generation and chain ordering are owned by upstream mitmproxy.
This module only supplies display and event metadata for the active option.
"""

import hashlib
from functools import lru_cache

def _common_name(name):
    from cryptography.x509.oid import NameOID

    return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _describe(cert):
    from cryptography.hazmat.primitives import hashes, serialization

    public = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "name": _common_name(cert.subject),
        "issued_by": _common_name(cert.issuer),
        "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "spki_sha256": hashlib.sha256(public).hexdigest().upper(),
    }


@lru_cache(maxsize=1)
def _authorities():
    # The local API contract tests run without mitmproxy installed. Import the
    # bundled certificates only when status or a TLS event needs metadata.
    from mitmproxy.certs import EMUDHRA_CHAIN_PEM
    from cryptography import x509

    certificates = x509.load_pem_x509_certificates(EMUDHRA_CHAIN_PEM)
    if len(certificates) != 3:
        raise RuntimeError("Unexpected upstream eMudhra certificate chain")
    modern, legacy = _describe(certificates[0]), _describe(certificates[-1])
    if modern["name"] != "EM OV TLS CA - G3C" or legacy["name"] != modern["name"]:
        raise RuntimeError("Unexpected upstream eMudhra intermediate")
    if modern["spki_sha256"] != legacy["spki_sha256"]:
        raise RuntimeError("Upstream eMudhra cross-signs use different keys")
    return modern, legacy


def authority_details(old=False):
    modern, legacy = _authorities()
    return dict(legacy if old else modern)
