import os
import base64
import json
from typing import Optional, Dict, Any
import logging
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_ENV_KEY = 'AES256_KEY'
logger = logging.getLogger('backend.crypto')


def _get_key() -> bytes:
    """Return raw 32-byte AES key from `AES256_KEY` env var (base64 encoded).

    Raises a RuntimeError if the key is missing or invalid.
    """
    b64 = os.getenv(AES_ENV_KEY)
    if not b64:
        raise RuntimeError(f"Missing environment variable: {AES_ENV_KEY}")
    try:
        key = base64.b64decode(b64)
    except Exception:
        raise RuntimeError(f"Invalid base64 for {AES_ENV_KEY}")
    if len(key) != 32:
        raise RuntimeError(f"AES key must be 32 bytes (256 bits). Got {len(key)} bytes")
    return key


def encrypt_bytes(data: bytes) -> str:
    """Encrypt raw bytes and return base64(nonce + ciphertext).

    Uses AES-256-GCM with a 12-byte nonce.
    """
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    try:
        
        digest = hashlib.sha256(data).hexdigest()
        logger.info("Encrypted bytes: len=%d sha256=%s", len(data), digest)
    except Exception:
        logger.debug("Encrypted bytes (logging digest failed)")
    return base64.b64encode(nonce + ct).decode('utf-8')


def decrypt_bytes(b64: str) -> bytes:
    """Decrypt base64(nonce + ciphertext) and return plaintext bytes."""
    key = _get_key()
    raw = base64.b64decode(b64)
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    try:
        digest = hashlib.sha256(data).hexdigest()
        logger.info("Decrypted bytes: len=%d sha256=%s", len(data), digest)
    except Exception:
        logger.debug("Decrypted bytes (logging digest failed)")
    return data


def encrypt_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    b = text.encode('utf-8')
    out = encrypt_bytes(b)
    logger.debug("encrypt_text called: bytes=%d", len(b))
    return out


def decrypt_text(b64: Optional[str]) -> Optional[str]:
    if b64 is None:
        return None
    out = decrypt_bytes(b64).decode('utf-8')
    logger.debug("decrypt_text called: bytes=%d", len(out.encode('utf-8')))
    return out


def encrypt_json(obj: Optional[Dict[str, Any]]) -> Optional[str]:
    if obj is None:
        return None
    j = json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
    logger.debug("encrypt_json called: keys=%d", len(obj.keys()) if isinstance(obj, dict) else 0)
    return encrypt_text(j)


def decrypt_json(b64: Optional[str]) -> Optional[Dict[str, Any]]:
    if b64 is None:
        return None
    txt = decrypt_text(b64)
    try:
        obj = json.loads(txt)
        logger.debug("decrypt_json called: keys=%d", len(obj.keys()) if isinstance(obj, dict) else 0)
        return obj
    except Exception:
        return None
