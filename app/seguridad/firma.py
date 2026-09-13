"""
Strategy de firma digital.
"""
import hashlib
import base64
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

def canonicalizar_nota(paciente_id: str, personal_id: str, diagnostico: str, tratamiento: str, fecha_iso: str) -> str:
    return "|".join([paciente_id, personal_id, diagnostico, tratamiento, fecha_iso])

def hash_de_contenido(contenido_canonico: str) -> bytes:
    return hashlib.sha256(contenido_canonico.encode("utf-8")).digest()

class EstrategiaFirma(ABC):
    @abstractmethod
    def firmar(self, llave_privada, hash_bytes: bytes) -> bytes: ...
    @abstractmethod
    def verificar(self, llave_publica, hash_bytes: bytes, firma_bytes: bytes) -> bool: ...

class FirmaRSA(EstrategiaFirma):
    def firmar(self, llave_privada: RSAPrivateKey, hash_bytes: bytes) -> bytes:
        return llave_privada.sign(hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))
    def verificar(self, llave_publica: RSAPublicKey, hash_bytes: bytes, firma_bytes: bytes) -> bool:
        try:
            llave_publica.verify(firma_bytes, hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256())); return True
        except InvalidSignature: return False

class FirmaECDSA(EstrategiaFirma):
    def firmar(self, llave_privada: ec.EllipticCurvePrivateKey, hash_bytes: bytes) -> bytes:
        return llave_privada.sign(hash_bytes, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    def verificar(self, llave_publica: ec.EllipticCurvePublicKey, hash_bytes: bytes, firma_bytes: bytes) -> bool:
        try:
            llave_publica.verify(firma_bytes, hash_bytes, ec.ECDSA(utils.Prehashed(hashes.SHA256()))); return True
        except InvalidSignature: return False

_estrategia_activa: EstrategiaFirma = FirmaRSA()

def firmar_nota(llave_privada: RSAPrivateKey, hash_bytes: bytes) -> str:
    return base64.b64encode(_estrategia_activa.firmar(llave_privada, hash_bytes)).decode("utf-8")

def verificar_firma(llave_publica: RSAPublicKey, hash_bytes: bytes, firma_b64: str) -> bool:
    try: firma_bytes = base64.b64decode(firma_b64, validate=True)
    except (ValueError, TypeError): return False
    return _estrategia_activa.verificar(llave_publica, hash_bytes, firma_bytes)
