"""
Hashing y verificación de contraseñas con Argon2id.

Argon2id combina la resistencia a ataques de canal lateral de Argon2i
con la resistencia a ataques de GPU/ASIC de Argon2d.
Es el ganador del Password Hashing Competition 2015 y la primera opción
de OWASP desde 2021, por encima de bcrypt y PBKDF2.
Los parámetros por defecto de argon2-cffi (time=3, memory=64MB, parallelism=4)
cumplen el mínimo recomendado por OWASP.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_ph = PasswordHasher()


def hashear(contrasena: str) -> str:
    """Devuelve el hash Argon2id de la contraseña, listo para guardar en BD."""
    return _ph.hash(contrasena)


def verificar(hash_guardado: str, contrasena: str) -> bool:
    """True si la contraseña coincide con el hash. Nunca lanza excepción."""
    try:
        return _ph.verify(hash_guardado, contrasena)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validar_nueva(contrasena: str) -> tuple[bool, str]:
    """Política mínima: longitud 12-128, sin reglas artificiales de composición."""
    if len(contrasena) < 12:
        return False, "La contraseña debe tener al menos 12 caracteres."
    if len(contrasena) > 128:
        return False, "La contraseña no puede exceder 128 caracteres."
    return True, ""
