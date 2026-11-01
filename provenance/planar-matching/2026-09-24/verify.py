#!/usr/bin/env python3
"""Verify the fixed planar-matching PDF against its original September 24 timestamp.

Python 3 and OpenSSL 3 required. No network access or file modification.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

MANIFEST = '0a4aad21d819f0caf77320c80957a3c73362ed41c507f9100e7f1464a676cb78'
RESPONSE = '00591d74ce5242da9607528fa534e1e1486ebd9c9c52c218aed18e6325808983'
PDF = '5985ebd7983dcdad101ff972029d447761ddecaf93e3228e0f55f4b886ab58e1'
MEMBER = 'papers/AIRP-V3ZR-2MYB-U2ZZ/v3.1.0.pdf'
SIGNED = dt.datetime(2026, 9, 24, 4, 24, 14, tzinfo=dt.timezone.utc)
PINS = {
    'tsa.crt': '8bfb0305bb64e2571ca507552ef3245cb1c2fee8728e0ff8689225081ea13467',
    'cacert.pem': '2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438',
    'root_ca.crl': '13d85acc0dd6a7ace445822b09dcba0de4236e84d60494dcbe6d7a6c97031935',
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate manifest key')
        result[key] = value
    return result

def openssl_time(text):
    return dt.datetime.strptime(text.strip(), '%b %d %H:%M:%S %Y GMT').replace(tzinfo=dt.timezone.utc)

def verify(pdf_path, openssl):
    root = Path(__file__).resolve().parent
    def read(name):
        p = root / name
        require(p.is_file() and not p.is_symlink(), 'Missing evidence or symbolic link')
        return p.read_bytes()
    def run(args, data=None, check=True):
        p = subprocess.run([openssl] + args, input=data, capture_output=True, timeout=30)
        if check:
            require(p.returncode == 0, p.stderr.decode(errors='replace'))
        return p
    require('OpenSSL 3.' in run(['version']).stdout.decode(), 'Use OpenSSL 3')
    for name, expected in PINS.items():
        require(sha(read(name)) == expected, 'Certificate or archived CRL changed')
    manifest_bytes = read('release-manifest.json')
    require(sha(manifest_bytes) == MANIFEST, 'Original manifest changed')
    require(sha(read('response.tsr')) == RESPONSE, 'Original receipt changed')
    m = json.loads(manifest_bytes, object_pairs_hook=unique_pairs)
    require(set(m) == {'schema', 'digest_algorithm', 'files'} and m['schema'] == 'website-release-manifest-v1' and m['digest_algorithm'] == 'SHA-256', 'Unexpected manifest format')
    require(len(m['files']) == 57 and len({e['path'] for e in m['files']}) == 57, 'Unexpected manifest entries')
    entry = next((e for e in m['files'] if e['path'] == MEMBER), None)
    require(entry is not None and entry['sha256'] == PDF, 'PDF not bound by manifest')
    data = pdf_path.read_bytes()
    require(sha(data) == PDF and len(data) == entry['bytes'], 'PDF bytes do not match this version')
    ca, leaf, crl, trust, response = [str(root / n) for n in ['cacert.pem', 'tsa.crt', 'root_ca.crl', 'trust-and-crl.pem', 'response.tsr']]
    require(read('trust-and-crl.pem') == read('cacert.pem') + b'\n' + read('root_ca.crl'), 'Trust bundle changed')
    run(['crl', '-in', crl, '-verify', '-CAfile', ca, '-noout'])
    crl_text = run(['crl', '-in', crl, '-lastupdate', '-nextupdate', '-noout']).stdout.decode()
    first = openssl_time(re.search(r'^lastUpdate=(.+)$', crl_text, re.M).group(1))
    last = openssl_time(re.search(r'^nextUpdate=(.+)$', crl_text, re.M).group(1))
    require(first <= SIGNED <= last, 'Archived CRL does not cover signing time')
    leaf_text = run(['x509', '-in', leaf, '-text', '-noout']).stdout.decode()
    require(re.search(r'X509v3 Extended Key Usage: critical\s+Time Stamping\s*\n', leaf_text), 'Timestamp-only critical usage required')
    text = run(['ts', '-reply', '-in', response, '-text']).stdout.decode()
    require('Status: Granted.' in text and 'Hash Algorithm: sha256' in text, 'Invalid timestamp response')
    actual = openssl_time(re.search(r'^Time stamp: (.+)$', text, re.M).group(1))
    require(actual == SIGNED, 'Unexpected signed time')
    at = str(int(SIGNED.timestamp()))
    token = run(['ts', '-reply', '-in', response, '-token_out']).stdout
    # -nointern limits the actual signer to the pinned public certificate.
    run(['cms', '-verify', '-inform', 'DER', '-nointern', '-certfile', leaf,
         '-CAfile', trust, '-purpose', 'timestampsign', '-crl_check', '-attime', at], data=token)
    base = ['ts', '-verify', '-in', response, '-CAfile', trust, '-untrusted', leaf,
            '-crl_check', '-attime', at]
    run(base + ['-data', str(root / 'release-manifest.json')])
    negative = run(base + ['-digest', '0' * 64], check=False)
    require(negative.returncode != 0 and b'message imprint mismatch' in negative.stderr, 'Wrong-digest negative control failed')
    return {'status': 'PASS', 'member': MEMBER, 'pdf_sha256': PDF,
            'signed_at_utc': SIGNED.isoformat(), 'tsa_accuracy': 'unspecified',
            'trust': 'FreeTSA; verify root fingerprint independently',
            'revocation_evidence': 'archived CRL valid at signing time, not a current check',
            'checks': ['PDF bytes', 'original manifest', 'pinned signer', 'signature and certificate chain',
                       'critical timestamp usage', 'signed-time validity', 'archived CRL', 'wrong digest rejected']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pdf', type=Path)
    parser.add_argument('--openssl', default=shutil.which('openssl'))
    args = parser.parse_args()
    require(args.openssl, 'OpenSSL 3 is required')
    print(json.dumps(verify(args.pdf, args.openssl), indent=2))

if __name__ == '__main__':
    main()
