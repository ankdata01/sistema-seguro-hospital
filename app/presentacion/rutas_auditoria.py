"""
Rutas de auditoría: bitácora completa con estado de cada eslabón,
verificación de integridad on-demand, sesiones activas y exportación CSV.
"""
import csv
import io

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.config import DEMO_MODE
from app.fabrica import Fabrica
from app.presentacion.dependencias import (
    dep_conexion, usuario_actual,
    generar_csrf, validar_csrf, set_csrf_cookie,
)
from app.seguridad.cadena_hash import calcular_hash
from app.datos.repo_auditoria import RepoAuditoria

HASH_GENESIS = "0" * 64


def _enriquecer_entradas(entradas: list[dict]) -> list[dict]:
    hash_prev = HASH_GENESIS
    for entrada in entradas:
        esperado = calcular_hash(hash_prev, entrada["id"], entrada["personal_id"], entrada["entidad_afectada"], entrada["entidad_id"] or "", entrada["accion"], entrada["detalle"] or "", entrada["ip_origen"] or "", entrada["fecha_hora"])
        entrada["eslabón_valido"] = entrada["hash_anterior"] == hash_prev and esperado == entrada["hash_actual"]
        hash_prev = entrada["hash_actual"]
    return list(reversed(entradas))


def _auditar_verificacion(repo: RepoAuditoria, personal_id: str, ip: str) -> None:
    repo.insertar_encadenado(personal_id=personal_id, entidad_afectada="sistema", entidad_id=None, accion="VERIFICAR_INTEGRIDAD", detalle=None, ip_origen=ip)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "desconocido"


_ROLES_AUDITORIA = {"doctor", "admin", "administrativo"}


def _denegar(con, usuario: dict, request: Request, recurso: str):
    Fabrica(con).servicio_auth().registrar_acceso_denegado(usuario["sub"], recurso, _ip(request))
    return RedirectResponse(url="/panel?error=acceso_denegado", status_code=303)


def crear_router(plantillas: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["auditoría"])

    @router.get("/auditoria", response_class=HTMLResponse)
    async def ver_auditoria(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if usuario.get("rol") not in _ROLES_AUDITORIA:
            return _denegar(con, usuario, request, request.url.path)
        fab = Fabrica(con)
        entradas = _enriquecer_entradas(fab.repo_auditoria().listar_todos())
        csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "auditoria.html", {"usuario": usuario, "entradas": entradas, "csrf_token": csrf, "demo_mode": DEMO_MODE})
        set_csrf_cookie(resp, csrf)
        return resp

    @router.post("/auditoria/verificar", response_class=HTMLResponse)
    async def verificar(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if usuario.get("rol") not in _ROLES_AUDITORIA:
            return _denegar(con, usuario, request, request.url.path)
        form = await request.form()
        csrf_form = str(form.get("csrf_token", ""))
        if not validar_csrf(request, csrf_form):
            return await ver_auditoria(request, con, usuario)
        fab = Fabrica(con)
        resultado = fab.ejecutar_verificacion()
        _auditar_verificacion(fab.repo_auditoria(), usuario["sub"], _ip(request))
        for p in resultado["firmas_invalidas"]:
            fila = con.execute("SELECT diagnostico, tratamiento, personal_id, fecha FROM historial_clinico WHERE id = ?", (p["id"],)).fetchone()
            p["nota_actual"] = dict(fila) if fila else None
        entradas = _enriquecer_entradas(fab.repo_auditoria().listar_todos())
        csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "auditoria.html", {"usuario": usuario, "entradas": entradas, "resultado_verificacion": resultado, "csrf_token": csrf, "demo_mode": DEMO_MODE})
        set_csrf_cookie(resp, csrf)
        return resp

    _ACCIONES_SESION = {"PASSWORD_OK", "LOGIN_OK", "LOGIN_FALLIDO", "MFA_FALLIDO", "LOGOUT", "ACCESO_DENEGADO"}

    @router.get("/sesiones", response_class=HTMLResponse)
    async def ver_sesiones(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if usuario.get("rol") not in _ROLES_AUDITORIA:
            return _denegar(con, usuario, request, request.url.path)
        fab = Fabrica(con)
        todas = fab.repo_auditoria().listar_todos()
        sesiones = [e for e in reversed(todas) if e["accion"] in _ACCIONES_SESION]
        personal = {p["id"]: p["nombre"] for p in fab.repo_personal().listar_todos_incluyendo_inactivos()}
        csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "sesiones.html", {"usuario": usuario, "sesiones": sesiones, "personal": personal, "csrf_token": csrf, "demo_mode": DEMO_MODE})
        set_csrf_cookie(resp, csrf)
        return resp

    @router.get("/auditoria/exportar.csv")
    async def exportar_csv(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if usuario.get("rol") not in _ROLES_AUDITORIA:
            return _denegar(con, usuario, request, request.url.path)
        fab = Fabrica(con)
        entradas = fab.repo_auditoria().listar_todos()
        campos = ["id", "personal_id", "entidad_afectada", "entidad_id", "accion", "detalle", "ip_origen", "fecha_hora", "hash_anterior", "hash_actual"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=campos, extrasaction="ignore")
        writer.writeheader(); writer.writerows(entradas); buf.seek(0)
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=bitacora_auditoria.csv"})

    return router
