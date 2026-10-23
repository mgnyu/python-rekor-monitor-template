"""Certificate and signature helpers for the Rekor verifier."""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def extract_public_key(cert: bytes) -> bytes:
    """Return the public key of a PEM-encoded X.509 certificate, as PEM bytes."""
    certificate = x509.load_pem_x509_certificate(cert)
    public_key = certificate.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_artifact_signature(
    signature: bytes, public_key: bytes, artifact_filename: str
) -> bool:
    """Check an ECDSA-SHA256 signature over the artifact's contents.

    Returns True if the signature is valid and False if it is not. Other
    errors (unreadable file, malformed key) are raised to the caller.
    """
    key = load_pem_public_key(public_key)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError(f"expected an EC public key, got {type(key).__name__}")

    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    try:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
