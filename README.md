# SealPass

QR passes for attendance and event entry that cannot be copied, edited or forged.

Every QR carries two cryptographic locks:

1. **EC-Schnorr signature (P-256, SHA-256).** The Pass Authority signs the pass body: roll number, event, validity window and a random pass id. This proves who issued it, catches any edit, and gives non-repudiation.
2. **Rotating HMAC-SHA256 tag.** `HMAC(K_se, pass_id || floor(time/10))`. It is computed on the student's phone with a per-student, per-event key and changes every 10 seconds, so a screenshot stops working after about 20 seconds.

The gate runs ten checks in order: format, certificate chain, signature, event, validity window, freshness, HMAC tag, revocation, one-time use, then admit. Each admission is appended to a SHA-256 hash-chained ledger.

SHA-256, HMAC, P-256 arithmetic and Schnorr are written from scratch in `sealcrypto/`. They are checked against the FIPS 180-4 and RFC 4231 vectors, `hashlib`, `hmac` and OpenSSL. Use vetted libraries for production; these implementations are here so every step can be read and shown.

## Run locally

```
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
bash pki/make_pki.sh            # OpenSSL: root CA, Pass Authority cert, TLS cert for your LAN IP
python app.py
```

- Laptop: `https://localhost:5443` (the story), `/lab`, `/dashboard`
- Phones on the same Wi-Fi: open `/dashboard` and press "Connect phones" for QR links to `/phone` and `/gate`.
- The gate needs HTTPS for the live camera. Accept the certificate warning once, or install `root.cer` from the dashboard. "Take a photo instead" works over plain HTTP on port 5080.

If OpenSSL is not installed, `python pki/make_pki.py` builds the same PKI, and the app builds one automatically on first start.

## Tests

```
pytest
```

The 53 tests cover the known-answer vectors, the cross-checks against OpenSSL, Schnorr forgery attempts, every threat-lab attack (each must be stopped at its expected step), ledger tampering, and a check that the browser crypto (`static/js/crypto.js`) gives byte-identical results to the Python code.

## Layout

| Path | What it is |
|---|---|
| `sealcrypto/` | SHA-256, HMAC, number theory, elliptic curves, Schnorr, key hierarchy |
| `core/` | pass format, issuer, 10-step verifier, ledger, PKI checks, threat lab, self-test |
| `pki/` | OpenSSL script and Python fallback |
| `templates/`, `static/` | story page, lab, phone, gate, dashboard |

## Hosting

On a serverless host, set `ROOT_CRT`, `AUTHORITY_CRT`, `AUTHORITY_KEY` (PEM text) and `K_MASTER` (64 hex characters) as environment variables, so that every instance shares the same keys. The host provides TLS.
