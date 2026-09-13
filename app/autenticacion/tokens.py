"""Emisión y validación de JWT con RS256 y validación de emisor/audiencia."""
import uuid
from datetime import datetime, timezone, timedelta

import jwt

from app.config import (
    LLAVE_SERVIDOR_PRIVADA,
    LLAVE_SERVIDOR_PUBLICA,
    JWT_ALGORITMO,
    JWT_EXPIRACION_MINUTOS,
    JWT_ISSUER,
    JWT_AUDIENCE,
    SECRET_KEY,
)
from app.seguridad.llaves import cargar_privada


def emitir(usuario: dict) -> str:
    ahora = datetime.now(timezone.utc)
    payload = {
        "sub": usuario["id"],
        "nombre": usuario["nombre"],
        "rol": usuario["rol"],
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": ahora,
        "nbf": ahora,
        "exp": ahora + timedelta(minutes=JWT_EXPIRACION_MINUTOS),
        "jti": str(uuid.uuid4()),
    }
    llave_privada = cargar_privada(LLAVE_SERVIDOR_PRIVADA, SECRET_KEY)
    return jwt.encode(payload, llave_privada, algorithm=JWT_ALGORITMO)


def validar(token: str) -> dict:
    llave_publica = LLAVE_SERVIDOR_PUBLICA.read_bytes()
    return jwt.decode(
        token,
        llave_publica,
        algorithms=[JWT_ALGORITMO],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti"]},
    )
