#!/usr/bin/env python3
"""Offline consistency checks for the two official Google Android roots.
Does not authenticate a live root-list download or run the Rust verifier.
Source: https://developer.android.com/privacy-and-security/security-key-attestation
"""
import hashlib
import ssl
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / 'linux/rbad/src/v2_store/attestation/roots'
PINS = {
    'google-android-2022.pem': 'cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc',
    'google-android-2026.pem': '6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0',
}

for filename, pin in PINS.items():
    path = ROOT / filename
    der = ssl.PEM_cert_to_DER_cert(path.read_text())
    assert hashlib.sha256(der).hexdigest() == pin, filename
    subprocess.run(['openssl', 'verify', '-CAfile', str(path), '-check_ss_sig', '-no_check_time', str(path)], check=True)
    print(f'PASS: {filename} DER SHA-256 matches documented pin; self-signature verified')
