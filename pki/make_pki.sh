#!/usr/bin/env bash
# Builds the small PKI the system trusts, using OpenSSL.
#
#   Campus Root CA  (self-signed, offline in real life)
#     |-- Pass Authority certificate   holds the P-256 key that signs passes
#     |-- TLS server certificate       for https:// on the laptop's LAN address
#
# Usage: bash pki/make_pki.sh [LAN_IP]
set -euo pipefail

cd "$(dirname "$0")"
OUT=out
mkdir -p "$OUT"

IP="${1:-}"
if [ -z "$IP" ]; then
  IP=$(python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('10.255.255.255', 1)); print(s.getsockname()[0])" 2>/dev/null || echo 127.0.0.1)
fi
echo "LAN address for the TLS certificate: $IP"

# Git Bash on Windows rewrites arguments that start with "/"; this stops it.
export MSYS_NO_PATHCONV=1

# 1. Root CA
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/root.key"
openssl req -x509 -new -key "$OUT/root.key" -sha256 -days 3650 \
  -subj "/O=Campus Security Office/CN=Campus Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/root.crt"

# 2. Pass Authority: the key that signs every pass (used for Schnorr signatures)
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/authority.key"
openssl req -new -key "$OUT/authority.key" -subj "/O=Campus Security Office/CN=Pass Authority" -out "$OUT/authority.csr"
cat > "$OUT/authority.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
EOF
openssl x509 -req -in "$OUT/authority.csr" -CA "$OUT/root.crt" -CAkey "$OUT/root.key" -CAcreateserial \
  -days 825 -sha256 -extfile "$OUT/authority.ext" -out "$OUT/authority.crt"

# 3. TLS server certificate for the demo laptop
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/server.key"
openssl req -new -key "$OUT/server.key" -subj "/O=Campus Security Office/CN=SealPass Server" -out "$OUT/server.csr"
cat > "$OUT/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$IP
EOF
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/root.crt" -CAkey "$OUT/root.key" -CAcreateserial \
  -days 825 -sha256 -extfile "$OUT/server.ext" -out "$OUT/server.crt"

# DER copy of the root, which phones accept as an installable CA certificate.
openssl x509 -in "$OUT/root.crt" -outform DER -out "$OUT/root.cer"
echo "$IP" > "$OUT/lan_ip.txt"
rm -f "$OUT"/*.csr "$OUT"/*.ext

echo
openssl verify -CAfile "$OUT/root.crt" "$OUT/authority.crt" "$OUT/server.crt"
openssl x509 -in "$OUT/authority.crt" -noout -subject -issuer -dates
