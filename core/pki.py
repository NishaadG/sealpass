"""Loads the X.509 material and checks the chain the gate relies on."""

import datetime
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HOSTED = bool(os.environ.get("VERCEL"))
# Serverless hosts have a read-only code directory, so keys live under /tmp there.
PKI_DIR = Path("/tmp/sealpass-pki") if HOSTED else Path(__file__).resolve().parent.parent / "pki" / "out"
ENV_FILES = {"ROOT_CRT": "root.crt", "AUTHORITY_CRT": "authority.crt", "AUTHORITY_KEY": "authority.key"}


@dataclass
class ChainResult:
    ok: bool
    detail: str
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    public_key: tuple = None


def ensure_pki():
    # On a host, every instance must share one PKI, so it comes from environment variables.
    if all(os.environ.get(k) for k in ENV_FILES):
        PKI_DIR.mkdir(parents=True, exist_ok=True)
        for var, name in ENV_FILES.items():
            (PKI_DIR / name).write_text(os.environ[var].replace("\\n", "\n"))
    if not (PKI_DIR / "authority.crt").exists():
        from pki.make_pki import build, lan_ip
        build(lan_ip())


def load_cert(name: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate((PKI_DIR / f"{name}.crt").read_bytes())


def load_private_scalar(name: str) -> int:
    key = serialization.load_pem_private_key((PKI_DIR / f"{name}.key").read_bytes(), password=None)
    return key.private_numbers().private_value


def check_chain(cert: x509.Certificate, root: x509.Certificate, now=None) -> ChainResult:
    """Is `cert` signed by the pinned root, inside its validity period, and
    allowed to make digital signatures? Returns the P-256 public key if so."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
    base = dict(subject=subject, issuer=issuer, not_after=cert.not_valid_after_utc.strftime("%Y-%m-%d"))
    if cert.issuer != root.subject:
        return ChainResult(False, "issuer is not the pinned Campus Root CA", **base)
    try:
        root.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                 ec.ECDSA(cert.signature_hash_algorithm or hashes.SHA256()))
    except InvalidSignature:
        return ChainResult(False, "root signature on the certificate does not verify", **base)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return ChainResult(False, "certificate is outside its validity period", **base)
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.digital_signature:
        return ChainResult(False, "certificate is not allowed to sign", **base)
    pub = cert.public_key()
    if not isinstance(pub.curve, ec.SECP256R1):
        return ChainResult(False, "certified key is not on P-256", **base)
    nums = pub.public_numbers()
    return ChainResult(True, "signed by pinned root, in date, key usage digitalSignature",
                       public_key=(nums.x, nums.y), **base)
