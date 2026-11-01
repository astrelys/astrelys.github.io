# Planar matching: version 3.1.0, September 24 timestamp

This package contains the original RFC 3161 receipt for a website release manifest, public certificates, an archived revocation list and a portable verifier. The original manifest includes this exact PDF:

`papers/AIRP-V3ZR-2MYB-U2ZZ/v3.1.0.pdf`

SHA-256: `5985ebd7983dcdad101ff972029d447761ddecaf93e3228e0f55f4b886ab58e1`

Signed time: 2026-09-24 04:24:14 UTC. The timestamp authority did not specify accuracy.

## Verification

1. Extract all files into a new folder. Obtain the fixed-version PDF from https://astrelys.github.io/papers/AIRP-V3ZR-2MYB-U2ZZ/v3.1.0.pdf and save it as v3.1.0.pdf.
2. Install Python 3 and OpenSSL 3 if necessary. The program uses only the Python standard library and OpenSSL; it does not download anything.
3. Run `python3 verify.py v3.1.0.pdf`. If OpenSSL 3 is not the default, add `--openssl /path/to/openssl`.

The verifier checks the PDF against its entry in the unchanged original manifest, then verifies the timestamp and its trust material at signing time. The original manifest covers 57 files; this portable verifier checks only the stated PDF member. It also requires a deliberately wrong digest to be rejected. To test a changed PDF, alter a copy and run the same command: it must fail.

## Trust and scope

The FreeTSA root certificate is a trust assumption. Confirm it independently, for example through an independently authenticated copy of the FreeTSA public root. PEM file SHA-256: `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438`. This file fingerprint is distinct from the certificate's DER fingerprint printed by OpenSSL x509.

The archived CRL supports the recorded signing-time check, not a current revocation check. The timestamp supports existence of the exact PDF bytes by the signed time; it does not authenticate the manuscript author, originality or the exact first-publication second.

No manuscript sources, private request logs or website-operation records are included.
