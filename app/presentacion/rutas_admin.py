"""
Rutas de administración — gestión de usuarios del sistema.
Solo accesibles para usuarios con rol='admin'.

GET  /admin                  → lista de personal activo/inactivo
GET  /admin/nuevo            → formulario de alta de usuario
POST /admin/nuevo            → crea usuario, muestra QR de TOTP
POST /admin/usuarios/{id}/toggle → activa/desactiva un usuario
"""
import base64
import io
import uuid

import pyotp
import qrcode
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import DEMO_MODE, LLAVES_DIR
from app.autenticacion import passwords
from app.datos.repo_auditoria import RepoAuditoria
from app.datos.repo_personal import RepoPersonal
from app.fabrica import Fabrica
from app.presentacion.dependencias import (
    dep_conexion, usuario_actual,
    generar_csrf, validar_csrf, set_csrf_cookie,
)
from app.seguridad.llaves import generar_par_rsa, serializar_publica, guardar_privada_cifrada
from app.seguridad.secretos import cifrar_secreto

ISSUER_TOTP = "Clínica Segura"


def _ip(request: Request) -> str:
    return request.client.host if request.client else "desconocido"


def _auditar(repo: RepoAuditoria, personal_id: str | None, accion: str, detalle: str, ip: str) -> None:
    repo.insertar_encadenado(
        personal_id=personal_id,
        entidad_afectada="personal",
        entidad_id=None,
        accion=accion,
        detalle=detalle,
        ip_origen=ip,
    )


def _qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def _solo_admin(usuario: dict) -> bool:
    return usuario.get("rol") == "admin"


def _denegar_admin(con, usuario: dict, request: Request):
    Fabrica(con).servicio_auth().registrar_acceso_denegado(
        usuario["sub"], request.url.path, _ip(request)
    )
    return RedirectResponse(url="/panel?error=acceso_denegado", status_code=303)


def crear_router(plantillas) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"])

    @router.get("", response_class=HTMLResponse)
    async def panel_admin(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _solo_admin(usuario):
            return _denegar_admin(con, usuario, request)
        personal = RepoPersonal(con).listar_todos_incluyendo_inactivos()
        csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "admin.html", {"usuario": usuario, "personal": personal, "csrf_token": csrf, "demo_mode": DEMO_MODE})
        set_csrf_cookie(resp, csrf)
        return resp

    @router.get("/nuevo", response_class=HTMLResponse)
    async def form_nuevo(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _solo_admin(usuario):
            return _denegar_admin(con, usuario, request)
        csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "admin_nuevo.html", {"usuario": usuario, "csrf_token": csrf, "demo_mode": DEMO_MODE})
        set_csrf_cookie(resp, csrf)
        return resp

    @router.post("/nuevo", response_class=HTMLResponse)
    async def crear_usuario(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _solo_admin(usuario):
            return _denegar_admin(con, usuario, request)
        form = await request.form()
        csrf_form = str(form.get("csrf_token", ""))
        nombre = str(form.get("nombre", "")).strip()
        email = str(form.get("email", "")).strip().lower()
        rol = str(form.get("rol", "doctor"))
        especialidad = str(form.get("especialidad", "")).strip() or None
        pass_temp = str(form.get("password", "")).strip()

        def _error(msg: str):
            csrf = generar_csrf()
            resp = plantillas.TemplateResponse(request, "admin_nuevo.html", {"usuario": usuario, "error": msg, "csrf_token": csrf, "demo_mode": DEMO_MODE})
            set_csrf_cookie(resp, csrf)
            return resp

        if not validar_csrf(request, csrf_form):
            return _error("Token de seguridad inválido. Recarga la página.")
        if not nombre or not email or not pass_temp:
            return _error("Nombre, correo y contraseña son obligatorios.")
        if rol not in ("doctor", "enfermero", "administrativo", "admin"):
            return _error("Rol no válido.")
        password_ok, password_error = passwords.validar_nueva(pass_temp)
        if not password_ok:
            return _error(password_error)
        if RepoPersonal(con).obtener_por_email_incluyendo_inactivos(email) is not None:
            return _error(f"El correo {email} ya está registrado, aunque la cuenta esté inactiva.")

        uid = str(uuid.uuid4())
        priv, pub = generar_par_rsa()
        LLAVES_DIR.mkdir(exist_ok=True)
        guardar_privada_cifrada(priv, LLAVES_DIR / f"personal_{uid}.pem", pass_temp)
        mfa_secret = pyotp.random_base32()
        totp_uri = pyotp.TOTP(mfa_secret).provisioning_uri(email, issuer_name=ISSUER_TOTP)
        qr_data = _qr_data_uri(totp_uri)
        con.execute("""INSERT INTO personal (id, nombre, rol, especialidad, email, password_hash, mfa_secret, llave_publica, activo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""", (uid, nombre, rol, especialidad, email, passwords.hashear(pass_temp), cifrar_secreto(mfa_secret), serializar_publica(pub)))
        con.commit()
        _auditar(RepoAuditoria(con), usuario["sub"], "CREAR_USUARIO", f"email={email} rol={rol}", _ip(request))
        csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "admin_qr.html", {"usuario": usuario, "nuevo": {"nombre": nombre, "email": email, "rol": rol}, "totp_uri": totp_uri, "qr_data": qr_data, "csrf_token": csrf, "demo_mode": DEMO_MODE})
        set_csrf_cookie(resp, csrf)
        return resp

    @router.post("/usuarios/{uid}/toggle", response_class=HTMLResponse)
    async def toggle_usuario(request: Request, uid: str, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _solo_admin(usuario):
            return _denegar_admin(con, usuario, request)
        form = await request.form()
        if not validar_csrf(request, str(form.get("csrf_token", ""))):
            return RedirectResponse(url="/admin", status_code=303)
        fila = con.execute("SELECT activo, email FROM personal WHERE id = ?", (uid,)).fetchone()
        if fila:
            nuevo_estado = 0 if fila["activo"] else 1
            con.execute("UPDATE personal SET activo = ? WHERE id = ?", (nuevo_estado, uid))
            con.commit()
            accion = "ACTIVAR_USUARIO" if nuevo_estado else "DESACTIVAR_USUARIO"
            _auditar(RepoAuditoria(con), usuario["sub"], accion, f"email={fila['email']}", _ip(request))
        return RedirectResponse(url="/admin", status_code=303)

    @router.post("/usuarios/{uid}/eliminar", response_class=HTMLResponse)
    async def eliminar_usuario(request: Request, uid: str, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _solo_admin(usuario):
            return _denegar_admin(con, usuario, request)
        form = await request.form()
        if not validar_csrf(request, str(form.get("csrf_token", ""))):
            return RedirectResponse(url="/admin", status_code=303)
        fila = con.execute("SELECT activo, email, nombre FROM personal WHERE id = ?", (uid,)).fetchone()
        if not fila:
            return RedirectResponse(url="/admin", status_code=303)
        if fila["activo"]:
            return RedirectResponse(url="/admin?error=suspender_primero", status_code=303)
        if uid == usuario["sub"]:
            return RedirectResponse(url="/admin", status_code=303)
        entradas_audit = con.execute("SELECT COUNT(*) FROM audit_log WHERE personal_id = ?", (uid,)).fetchone()[0]
        if entradas_audit > 0:
            return RedirectResponse(url="/admin?error=tiene_auditoria", status_code=303)
        _auditar(RepoAuditoria(con), usuario["sub"], "ELIMINAR_USUARIO", f"email={fila['email']} nombre={fila['nombre']}", _ip(request))
        con.execute("DELETE FROM personal WHERE id = ?", (uid,))
        con.commit()
        return RedirectResponse(url="/admin", status_code=303)

    return router
