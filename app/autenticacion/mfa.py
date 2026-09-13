"""Segundo factor TOTP (RFC 6238) con secreto protegido en reposo."""
import pyotp

from app.seguridad.secretos import descifrar_secreto


def validar_totp(secret_protegido: str, codigo: str) -> bool:
    secreto = descifrar_secreto(secret_protegido)
    return pyotp.TOTP(secreto).verify(codigo.strip(), valid_window=1)


def codigo_actual(secret_protegido: str) -> str:
    secreto = descifrar_secreto(secret_protegido)
    return pyotp.TOTP(secreto).now()
