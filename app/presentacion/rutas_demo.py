"""
Panel de demostración — simula ataques para mostrar los mecanismos de defensa.

Rutas:
  GET  /demo                 → panel con estado actual
  POST /demo/atacar          → corrompe una nota en historial_clinico (UPDATE directo)
  POST /demo/borrar_bitacora → intenta DELETE en audit_log (trigger lo rechaza)
  POST /demo/restaurar       → re-ejecuta db/semilla.py para volver al estado limpio
  GET  /demo/codigos         → muestra códigos TOTP actuales de cada usuario de prueba

Solo disponible cuando DEMO_MODE=True (config.py).
"""
import os
import subprocess
import sys

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import DB_PATH, DEMO_MODE, DEMO_TOTP_VIEWER, COOKIE_TOKEN_NOMBRE, COOKIE_PREFACTOR_NOMBRE
from app.datos.repo_auditoria import RepoAuditoria
from app.fabrica import Fabrica
from app.presentacion.dependencias import dep_conexion, usuario_actual, generar_csrf, validar_csrf, set_csrf_cookie, COOKIE_CSRF


def _ip(request: Request) -> str:
    return request.client.host if request.client else "desconocido"


def _auditar_ataque(repo: RepoAuditoria, personal_id: str, accion: str, detalle: str, ip: str) -> None:
    repo.insertar_encadenado(personal_id=personal_id, entidad_afectada="demo", entidad_id=None, accion=accion, detalle=detalle, ip_origen=ip)

_ROLES_DEMO = {"doctor", "admin"}


def _autorizar_demo(con, usuario: dict, request: Request):
    if usuario.get("rol") in _ROLES_DEMO:
        return None
    Fabrica(con).servicio_auth().registrar_acceso_denegado(usuario["sub"], request.url.path, _ip(request))
    return RedirectResponse(url="/panel?error=acceso_denegado", status_code=303)


def crear_router(plantillas: Jinja2Templates) -> APIRouter:
    router = APIRouter(prefix="/demo", tags=["demo"])

    @router.get("", response_class=HTMLResponse)
    async def panel_demo(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        denegado = _autorizar_demo(con, usuario, request)
        if denegado: return denegado
        fab = Fabrica(con); estado = fab.ejecutar_verificacion(); csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "demo.html", {"usuario": usuario, "estado": estado, "csrf_token": csrf, "totp_viewer": DEMO_TOTP_VIEWER, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp

    @router.post("/atacar", response_class=HTMLResponse)
    async def atacar(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        denegado = _autorizar_demo(con, usuario, request)
        if denegado: return denegado
        form = await request.form()
        if not validar_csrf(request, str(form.get("csrf_token", ""))): return RedirectResponse(url="/demo", status_code=303)
        import sqlite3
        cx = sqlite3.connect(str(DB_PATH))
        try:
            fila = cx.execute("SELECT id FROM historial_clinico ORDER BY fecha LIMIT 1").fetchone()
            if fila:
                nota_id = fila[0]; cx.execute("UPDATE historial_clinico SET diagnostico = 'DATO MANIPULADO POR ATACANTE' WHERE id = ?", (nota_id,)); cx.commit(); detalle = f"nota_id={nota_id}"
            else: detalle = "no_habia_notas"
        finally: cx.close()
        _auditar_ataque(RepoAuditoria(con), usuario["sub"], "ATAQUE_SIMULADO", detalle, _ip(request))
        return RedirectResponse(url="/demo?ataque=ok", status_code=303)

    @router.post("/borrar_bitacora", response_class=HTMLResponse)
    async def borrar_bitacora(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        denegado = _autorizar_demo(con, usuario, request)
        if denegado: return denegado
        form = await request.form()
        if not validar_csrf(request, str(form.get("csrf_token", ""))): return RedirectResponse(url="/demo", status_code=303)
        import sqlite3
        cx = sqlite3.connect(str(DB_PATH))
        try:
            cx.execute("DELETE FROM audit_log"); cx.commit(); mensaje_trigger = "DELETE ejecutado (inesperado)"
        except (sqlite3.IntegrityError, sqlite3.OperationalError) as e: mensaje_trigger = str(e)
        finally: cx.close()
        _auditar_ataque(RepoAuditoria(con), usuario["sub"], "ATAQUE_SIMULADO", f"intento_borrar_bitacora: {mensaje_trigger}", _ip(request))
        return RedirectResponse(url=f"/demo?trigger={mensaje_trigger[:80]}", status_code=303)

    @router.post("/restaurar", response_class=HTMLResponse)
    async def restaurar(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        denegado = _autorizar_demo(con, usuario, request)
        if denegado: return denegado
        if not os.getenv("DEMO_PASSWORD", "").strip(): return RedirectResponse(url="/demo?restaurado=requires_password_env", status_code=303)
        form = await request.form()
        if not validar_csrf(request, str(form.get("csrf_token", ""))): return RedirectResponse(url="/demo", status_code=303)
        resultado = subprocess.run([sys.executable, "-m", "db.semilla"], capture_output=True, text=True, cwd=str(DB_PATH.parent.parent))
        if resultado.returncode != 0: return RedirectResponse(url="/demo?restaurado=error", status_code=303)
        resp = RedirectResponse(url="/login?restaurado=ok", status_code=303); resp.delete_cookie(COOKIE_TOKEN_NOMBRE); resp.delete_cookie(COOKIE_PREFACTOR_NOMBRE); resp.delete_cookie(COOKIE_CSRF); return resp

    @router.get("/codigos", response_class=HTMLResponse)
    async def ver_codigos(request: Request, con=Depends(dep_conexion)):
        if not DEMO_TOTP_VIEWER: raise HTTPException(status_code=404)
        host = request.client.host if request.client else ""
        if host not in {"127.0.0.1", "::1", "localhost", "testclient"}: raise HTTPException(status_code=403, detail="Visor TOTP solo disponible en loopback")
        from app.autenticacion import mfa
        personal = Fabrica(con).repo_personal().listar_todos()
        codigos = [{"nombre": p["nombre"], "email": p["email"], "codigo": mfa.codigo_actual(p["mfa_secret"])} for p in personal]
        return plantillas.TemplateResponse(request, "demo_codigos.html", {"usuario": None, "codigos": codigos, "csrf_token": "", "demo_mode": DEMO_MODE})

    return router
