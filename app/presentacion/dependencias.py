"""
Dependencias compartidas entre rutas protegidas.

usuario_actual: valida el JWT en cada petición protegida.
dep_conexion:   abre y cierra la conexión SQLite por petición.
Utilidades CSRF: patrón double-submit cookie.
"""
import secrets

import jwt
from fastapi import Depends, Request
from fastapi.responses import RedirectResponse

from app.autenticacion import tokens
from app.config import COOKIE_TOKEN_NOMBRE, COOKIE_SECURE
from app.datos.conexion import obtener_conexion
from app.datos.repo_personal import RepoPersonal


class NoAutenticado(Exception):
    pass


def dep_conexion():
    con = obtener_conexion()
    try:
        yield con
    finally:
        con.close()


async def usuario_actual(request: Request, con=Depends(dep_conexion)) -> dict:
    token = request.cookies.get(COOKIE_TOKEN_NOMBRE)
    if not token:
        raise NoAutenticado()
    try:
        claims = tokens.validar(token)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise NoAutenticado()

    usuario = RepoPersonal(con).obtener_por_id(str(claims.get("sub", "")))
    if usuario is None or usuario["rol"] != claims.get("rol"):
        raise NoAutenticado()
    claims["nombre"] = usuario["nombre"]
    claims["rol"] = usuario["rol"]
    return claims


COOKIE_CSRF = "csrf_token"


def generar_csrf() -> str:
    return secrets.token_hex(32)


def validar_csrf(request: Request, token_formulario: str | None) -> bool:
    token_cookie = request.cookies.get(COOKIE_CSRF)
    if not token_cookie or not token_formulario:
        return False
    return secrets.compare_digest(token_cookie, token_formulario)


def set_csrf_cookie(response, token: str) -> None:
    response.set_cookie(
        COOKIE_CSRF,
        token,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        max_age=3600,
        path="/",
    )
