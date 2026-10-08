"""Same PKI as make_pki.sh, for machines without the openssl command.

The `cryptography` package uses the OpenSSL library underneath, so the
certificates are identical in structure.  Usage: python pki/make_pki.py [LAN_IP]
"""

import datetime
import ipaddress
import os
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


OUT = Path("/tmp/sealpass-pki") if os.environ.get("VERCEL") else Path(__file__).parent / "out"


def lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Campus Security Office"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _save_key(key, path):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))


def _cert(subject, key, issuer, issuer_key, days, ca, usage, extra=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(usage, critical=True))
    for ext in extra:
        b = b.add_extension(ext, critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _usage(**on):
    names = ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only"]
    return x509.KeyUsage(**{n: on.get(n, False) for n in names})


def build(ip: str):
    OUT.mkdir(parents=True, exist_ok=True)
    curve = ec.SECP256R1()
    root_key, auth_key, srv_key = (ec.generate_private_key(curve) for _ in range(3))
    root = _cert(_name("Campus Root CA"), root_key, _name("Campus Root CA"), root_key, 3650, True,
                 _usage(key_cert_sign=True, crl_sign=True))
    auth = _cert(_name("Pass Authority"), auth_key, root.subject, root_key, 825, False,
                 _usage(digital_signature=True, content_commitment=True))
    srv = _cert(_name("SealPass Server"), srv_key, root.subject, root_key, 825, False,
                _usage(digital_signature=True),
                [x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                 x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                              x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                              x509.IPAddress(ipaddress.ip_address(ip))])])
    for name, key, cert in (("root", root_key, root), ("authority", auth_key, auth), ("server", srv_key, srv)):
        _save_key(key, OUT / f"{name}.key")
        (OUT / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (OUT / "root.cer").write_bytes(root.public_bytes(serialization.Encoding.DER))
    (OUT / "lan_ip.txt").write_text(ip)
    print(f"PKI written to {OUT} (TLS certificate covers {ip})")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else lan_ip())
