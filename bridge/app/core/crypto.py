"""
Crypto security engine implementing Ed25519 offline license signing and verification.
Uses standard cryptography library; zero proprietary / invented crypto protocols.
"""
import base64
import hmac
import hashlib
import json
import os
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Default file path for persisted signing key
_DEFAULT_KEY_PATH = Path(os.environ.get("SIGNING_KEY_PATH", "signing_key.pem"))


def _load_or_generate_key() -> ed25519.Ed25519PrivateKey:
    """
    Load persistent Ed25519 private key from:
      1. SIGNING_KEY_PEM env var (raw PEM text)
      2. File at SIGNING_KEY_PATH env var (or default signing_key.pem)
      3. Generate fresh key and persist to that file path.
    """
    pem_env = os.environ.get("SIGNING_KEY_PEM")
    if pem_env:
        pem_bytes = pem_env.encode() if isinstance(pem_env, str) else pem_env
        return serialization.load_pem_private_key(pem_bytes, password=None)

    if _DEFAULT_KEY_PATH.exists():
        return serialization.load_pem_private_key(_DEFAULT_KEY_PATH.read_bytes(), password=None)

    key = ed25519.Ed25519PrivateKey.generate()
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _DEFAULT_KEY_PATH.write_bytes(pem_bytes)
    return key


def verify_hmac_signature(secret: str, payload_bytes: bytes, signature: str) -> bool:
    """
    Verify HMAC-SHA256 webhook signature using constant-time compare.
    Supports bare hex digest and "sha256=<hex>" prefix (GitHub-style).
    Returns False (fail-closed) on any error, missing secret, or missing/invalid signature.
    """
    if not secret or not signature:
        return False
    try:
        expected = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        sig = signature.removeprefix("sha256=")
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


class CryptoEngine:
    def __init__(self, private_key_pem: bytes = None, public_key_pem: bytes = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            self.public_key = self.private_key.public_key()
        elif public_key_pem:
            self.private_key = None
            self.public_key = serialization.load_pem_public_key(public_key_pem)
        else:
            # Persistent key: env var → file → generate-and-persist
            self.private_key = _load_or_generate_key()
            self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_private_key_pem(self) -> bytes:
        if not self.private_key:
            raise ValueError("No private key configured on client side")
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign_payload(self, payload_dict: dict) -> Tuple[str, str]:
        if not self.private_key:
            raise ValueError("Server private key required for signing")
        json_bytes = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
        raw_sig = self.private_key.sign(json_bytes)
        cert_b64 = base64.b64encode(json_bytes).decode('utf-8')
        sig_b64 = base64.b64encode(raw_sig).decode('utf-8')
        return cert_b64, sig_b64

    def verify_payload(self, cert_b64: str, sig_b64: str) -> Tuple[bool, dict, str]:
        try:
            json_bytes = base64.b64decode(cert_b64)
            raw_sig = base64.b64decode(sig_b64)
            self.public_key.verify(raw_sig, json_bytes)
            data = json.loads(json_bytes.decode('utf-8'))
            return True, data, "OK"
        except InvalidSignature:
            return False, {}, "INVALID_SIGNATURE: Cryptographic tampering detected"
        except Exception as e:
            return False, {}, f"VERIFICATION_ERROR: {str(e)}"
