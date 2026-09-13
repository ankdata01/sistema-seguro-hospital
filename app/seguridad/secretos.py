"""Protección AES-256-GCM de secretos TOTP almacenados en SQLite."""
import base64, os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from app.config import SECRET_KEY
_PREFIX="enc:v1:"
_AAD=b"sistema-seguro-hospital:mfa-secret:v1"
_SALT=b"sistema-seguro-hospital-v1"
# Compatibilidad criptográfica con secretos generados antes del cambio de identidad.
_LEGACY_AAD=bytes.fromhex("636c696e6963612d7365677572613a6d66612d7365637265743a7631")
_LEGACY_SALT=bytes.fromhex("636c696e6963612d7365677572612d7631")
def _clave(salt=_SALT):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"mfa-secrets").derive(SECRET_KEY.encode("utf-8"))
def cifrar_secreto(valor: str) -> str:
    nonce=os.urandom(12); cifrado=AESGCM(_clave()).encrypt(nonce,valor.encode("utf-8"),_AAD); return _PREFIX+base64.urlsafe_b64encode(nonce+cifrado).decode("ascii")
def descifrar_secreto(valor: str) -> str:
    if not valor.startswith(_PREFIX): return valor
    raw=base64.urlsafe_b64decode(valor[len(_PREFIX):].encode("ascii")); nonce,cifrado=raw[:12],raw[12:]
    try:
        return AESGCM(_clave()).decrypt(nonce,cifrado,_AAD).decode("utf-8")
    except InvalidTag:
        return AESGCM(_clave(_LEGACY_SALT)).decrypt(nonce,cifrado,_LEGACY_AAD).decode("utf-8")
