"""Verify one Sigstore bundle's DSSE envelope offline and print the verified payload as JSON.

This is the external verifier ACB-PROV-003 runs (docs/provenance-design.md section 6). It runs from
its own environment with sigstore-python, so acb itself keeps no signature dependency. It checks the
certificate chain, transparency log entry, signer identity and DSSE signature against the given
ClientTrustConfig, never fetching trust material, and does not interpret the statement.

    acb-sigstore-verify --trust-config FILE --bundle FILE --policy ISSUER IDENTITY [--policy ...]

Exit 0 prints {"payload_type", "payload" (base64), "certificate": {"issuer", "san", "build_signer_uri",
"source_repository_uri"}}. Exit 3 prints {"rejected": reason} when the bundle does not verify or
matches no policy. Any other exit means the verifier could not give an answer.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat import asn1
from cryptography.x509 import (
    Certificate,
    ExtensionNotFound,
    ObjectIdentifier,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from sigstore.errors import VerificationError
from sigstore.models import Bundle, ClientTrustConfig, InvalidBundle
from sigstore.verify import Verifier
from sigstore.verify.policy import AnyOf, Identity

REJECTED_EXIT = 3
_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OTHERNAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.7")
_BUILD_SIGNER_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.9")
_SOURCE_REPOSITORY_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.12")


def _extension(cert: Certificate, oid: ObjectIdentifier, *, der: bool) -> str | None:
    """Return an extension's string value, decoded the way sigstore-python's policies decode it."""
    try:
        raw = cert.extensions.get_extension_for_oid(oid).value.value
    except ExtensionNotFound:
        return None
    return asn1.decode_der(str, raw) if der else raw.decode()


def _sans(cert: Certificate) -> list[str]:
    """Return the identities sigstore-python's Identity policy compares against."""
    names = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
    values = [*names.get_values_for_type(RFC822Name), *names.get_values_for_type(UniformResourceIdentifier)]
    values.extend(
        name.value.decode() for name in names.get_values_for_type(OtherName) if name.type_id == _OTHERNAME_OID
    )
    return sorted(set(values))


def main(argv: list[str] | None = None) -> int:
    """Verify the bundle and print the result; return the exit status."""
    parser = argparse.ArgumentParser(prog="acb-sigstore-verify")
    parser.add_argument("--trust-config", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--policy", nargs=2, action="append", required=True, metavar=("ISSUER", "IDENTITY"))
    args = parser.parse_args(argv)

    config = ClientTrustConfig.from_json(args.trust_config.read_text(encoding="utf-8"))
    verifier = Verifier(trusted_root=config.trusted_root)
    policy = AnyOf([Identity(identity=identity, issuer=issuer) for issuer, identity in args.policy])
    try:
        bundle = Bundle.from_json(args.bundle.read_bytes())
        payload_type, payload = verifier.verify_dsse(bundle, policy)
    except (InvalidBundle, VerificationError) as exc:
        print(json.dumps({"rejected": str(exc)}))
        return REJECTED_EXIT

    cert = bundle.signing_certificate
    result = {
        "payload_type": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "certificate": {
            "issuer": _extension(cert, _ISSUER_OID, der=False),
            "san": _sans(cert),
            "build_signer_uri": _extension(cert, _BUILD_SIGNER_URI_OID, der=True),
            "source_repository_uri": _extension(cert, _SOURCE_REPOSITORY_URI_OID, der=True),
        },
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
