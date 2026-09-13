"""Rutas de autenticación — login en dos pasos y logout."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.autenticacion.servicio_auth import ServicioAuth, CredencialesInvalidas, CodigoMFAInvalido, UsuarioNoEncontrado
from app.seguridad.rate_limiter import esta_bloqueado, registrar_fallo, limpiar_exito, segundos_restantes
from app.config import COOKIE_PREFACTOR_NOMBRE, COOKIE_PREFACTOR_SEGUNDOS, COOKIE_TOKEN_NOMBRE, DEMO_MODE, SECRET_KEY, COOKIE_SECURE
from app.datos.repo_personal import RepoPersonal
from app.datos.repo_auditoria import RepoAuditoria
from app.presentacion.dependencias import dep_conexion, generar_csrf, validar_csrf, set_csrf_cookie, COOKIE_CSRF

_SALT_PREFACTOR = "pre-auth-v1"

def _signer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(SECRET_KEY, salt=_SALT_PREFACTOR)

def _ip(request: Request) -> str:
    return request.client.host if request.client else "desconocido"

def crear_router(plantillas: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["autenticación"])

    @router.get("/login", response_class=HTMLResponse)
    async def mostrar_login(request: Request):
        csrf = generar_csrf(); resp = plantillas.TemplateResponse(request, "login.html", {"csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp

    @router.post("/login", response_class=HTMLResponse)
    async def procesar_login(request: Request, con=Depends(dep_conexion)):
        form = await request.form(); email = str(form.get("email", "")).strip(); contrasena = str(form.get("contrasena", "")); csrf_form = str(form.get("csrf_token", ""))
        def _error(msg: str):
            csrf = generar_csrf(); resp = plantillas.TemplateResponse(request, "login.html", {"error": msg, "csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp
        if not validar_csrf(request, csrf_form): return _error("Token de seguridad inválido. Recarga la página.")
        if not email or not contrasena: return _error("Completa todos los campos.")
        ip = _ip(request); clave_ip = f"ip:{ip}"; clave_email = f"email:{email}"
        if esta_bloqueado(clave_ip) or esta_bloqueado(clave_email):
            secs = max(segundos_restantes(clave_ip), segundos_restantes(clave_email)); return _error(f"Demasiados intentos fallidos. Espera {secs // 60 + 1} min antes de intentarlo de nuevo.")
        svc = ServicioAuth(RepoPersonal(con), RepoAuditoria(con))
        try: usuario = svc.primer_factor(email, contrasena, ip)
        except CredencialesInvalidas:
            registrar_fallo(clave_ip); registrar_fallo(clave_email); return _error("Correo o contraseña incorrectos.")
        limpiar_exito(clave_email); limpiar_exito(clave_ip)
        token_prefactor = _signer().dumps({"user_id": usuario["id"]})
        resp = RedirectResponse(url="/login/mfa", status_code=303)
        resp.set_cookie(COOKIE_PREFACTOR_NOMBRE, token_prefactor, httponly=True, samesite="strict", secure=COOKIE_SECURE, max_age=COOKIE_PREFACTOR_SEGUNDOS, path="/")
        return resp

    @router.get("/login/mfa", response_class=HTMLResponse)
    async def mostrar_mfa(request: Request):
        if not request.cookies.get(COOKIE_PREFACTOR_NOMBRE): return RedirectResponse(url="/login", status_code=303)
        csrf = generar_csrf(); resp = plantillas.TemplateResponse(request, "mfa.html", {"csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp

    @router.post("/login/mfa", response_class=HTMLResponse)
    async def procesar_mfa(request: Request, con=Depends(dep_conexion)):
        form = await request.form(); codigo = str(form.get("codigo", "")).strip(); csrf_form = str(form.get("csrf_token", ""))
        def _error(msg: str):
            csrf = generar_csrf(); resp = plantillas.TemplateResponse(request, "mfa.html", {"error": msg, "csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp
        if not validar_csrf(request, csrf_form): return _error("Token de seguridad inválido. Recarga la página.")
        cookie_raw = request.cookies.get(COOKIE_PREFACTOR_NOMBRE)
        if not cookie_raw: return RedirectResponse(url="/login", status_code=303)
        try:
            datos = _signer().loads(cookie_raw, max_age=COOKIE_PREFACTOR_SEGUNDOS); user_id = datos["user_id"]
        except (BadSignature, SignatureExpired, KeyError):
            resp = RedirectResponse(url="/login", status_code=303); resp.delete_cookie(COOKIE_PREFACTOR_NOMBRE); return resp
        clave_mfa = f"mfa:{user_id}"
        if esta_bloqueado(clave_mfa):
            secs = segundos_restantes(clave_mfa); return _error(f"Demasiados intentos MFA fallidos. Espera {secs // 60 + 1} min.")
        svc = ServicioAuth(RepoPersonal(con), RepoAuditoria(con))
        try:
            jwt_token = svc.segundo_factor(user_id, codigo, _ip(request)); limpiar_exito(clave_mfa)
        except CodigoMFAInvalido:
            registrar_fallo(clave_mfa); return _error("Código incorrecto o expirado. Inténtalo de nuevo.")
        except UsuarioNoEncontrado: return RedirectResponse(url="/login", status_code=303)
        resp = RedirectResponse(url="/panel", status_code=303)
        resp.set_cookie(COOKIE_TOKEN_NOMBRE, jwt_token, httponly=True, samesite="strict", secure=COOKIE_SECURE, max_age=60 * 30, path="/")
        resp.delete_cookie(COOKIE_PREFACTOR_NOMBRE); return resp

    @router.post("/logout")
    async def logout(request: Request, con=Depends(dep_conexion)):
        import jwt as pyjwt
        from app.autenticacion import tokens as tk
        form = await request.form()
        if not validar_csrf(request, str(form.get("csrf_token", ""))): return RedirectResponse(url="/panel?error=csrf", status_code=303)
        user_id = None; token = request.cookies.get(COOKIE_TOKEN_NOMBRE)
        if token:
            try: user_id = tk.validar(token).get("sub")
            except pyjwt.InvalidTokenError: pass
        if user_id: ServicioAuth(RepoPersonal(con), RepoAuditoria(con)).registrar_logout(user_id, _ip(request))
        resp = RedirectResponse(url="/login", status_code=303); resp.delete_cookie(COOKIE_TOKEN_NOMBRE); resp.delete_cookie(COOKIE_PREFACTOR_NOMBRE); resp.delete_cookie(COOKIE_CSRF); return resp

    return router
