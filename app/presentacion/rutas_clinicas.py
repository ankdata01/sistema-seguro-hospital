"""
Rutas clínicas: lista de pacientes, historial, nueva nota firmada.

Control de acceso por rol:
  - doctor    → puede consultar y crear notas
  - enfermero → puede consultar, NO puede crear notas (ACCESO_DENEGADO auditado)
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.clinico.modelos import NotaClinica
from app.clinico.servicio_clinico import PacienteNoEncontrado
from app.config import DEMO_MODE, LLAVES_DIR
from app.fabrica import Fabrica
from app.presentacion.dependencias import dep_conexion, usuario_actual, generar_csrf, validar_csrf, set_csrf_cookie
from app.seguridad.firma import canonicalizar_nota, hash_de_contenido, firmar_nota
from app.seguridad.llaves import cargar_privada


def _ip(request: Request) -> str:
    return request.client.host if request.client else "desconocido"


def _iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_ROLES_VER_EXPEDIENTES = {"doctor", "enfermero", "administrativo"}

def _puede_ver_expedientes(usuario: dict) -> bool:
    return usuario.get("rol") in _ROLES_VER_EXPEDIENTES

def _denegar_acceso(con, usuario: dict, recurso: str, ip: str):
    Fabrica(con).servicio_auth().registrar_acceso_denegado(usuario["sub"], recurso, ip)
    return RedirectResponse(url="/panel?error=acceso_denegado", status_code=303)


def crear_router(plantillas: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["clínico"])

    @router.get("/pacientes", response_class=HTMLResponse)
    async def listar_pacientes(request: Request, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _puede_ver_expedientes(usuario): return _denegar_acceso(con, usuario, "/pacientes", _ip(request))
        fab = Fabrica(con); pacientes = fab.servicio_clinico().listar_pacientes(); csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "pacientes.html", {"usuario": usuario, "pacientes": pacientes, "csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp

    @router.get("/pacientes/{paciente_id}", response_class=HTMLResponse)
    async def ver_historial(request: Request, paciente_id: str, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _puede_ver_expedientes(usuario): return _denegar_acceso(con, usuario, f"/pacientes/{paciente_id}", _ip(request))
        fab = Fabrica(con)
        try: paciente, notas = fab.servicio_clinico().obtener_historial(paciente_id, personal_id=usuario["sub"], ip=_ip(request))
        except PacienteNoEncontrado: return RedirectResponse(url="/pacientes", status_code=303)
        csrf = generar_csrf(); puede_crear = usuario.get("rol") == "doctor"
        resp = plantillas.TemplateResponse(request, "historial.html", {"usuario": usuario, "paciente": paciente, "notas": notas, "puede_crear_nota": puede_crear, "csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp

    @router.get("/pacientes/{paciente_id}/nota", response_class=HTMLResponse)
    async def formulario_nota(request: Request, paciente_id: str, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if usuario.get("rol") != "doctor":
            Fabrica(con).servicio_auth().registrar_acceso_denegado(usuario["sub"], f"/pacientes/{paciente_id}/nota", _ip(request)); return RedirectResponse(url=f"/pacientes/{paciente_id}?error=acceso_denegado", status_code=303)
        from app.datos.repo_pacientes import RepoPacientes
        from app.clinico.modelos import Paciente
        pac_dict = RepoPacientes(con).obtener_por_id(paciente_id)
        if pac_dict is None: return RedirectResponse(url="/pacientes", status_code=303)
        paciente = Paciente(**{k: pac_dict[k] for k in ("id", "nombre", "fecha_nacimiento", "contacto")}); csrf = generar_csrf()
        resp = plantillas.TemplateResponse(request, "nota_nueva.html", {"usuario": usuario, "paciente": paciente, "csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp

    @router.post("/pacientes/{paciente_id}/nota", response_class=HTMLResponse)
    async def crear_nota(request: Request, paciente_id: str, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if usuario.get("rol") != "doctor":
            Fabrica(con).servicio_auth().registrar_acceso_denegado(usuario["sub"], f"/pacientes/{paciente_id}/nota", _ip(request)); return RedirectResponse(url=f"/pacientes/{paciente_id}", status_code=303)
        form = await request.form(); diagnostico = str(form.get("diagnostico", "")).strip(); tratamiento = str(form.get("tratamiento", "")).strip(); contrasena_firma = str(form.get("contrasena_firma", "")); csrf_form = str(form.get("csrf_token", ""))
        from app.datos.repo_pacientes import RepoPacientes
        from app.clinico.modelos import Paciente
        pac_dict = RepoPacientes(con).obtener_por_id(paciente_id)
        if pac_dict is None: return RedirectResponse(url="/pacientes", status_code=303)
        paciente = Paciente(**{k: pac_dict[k] for k in ("id", "nombre", "fecha_nacimiento", "contacto")})
        def _error(msg: str):
            csrf = generar_csrf(); resp = plantillas.TemplateResponse(request, "nota_nueva.html", {"usuario": usuario, "paciente": paciente, "error": msg, "csrf_token": csrf, "demo_mode": DEMO_MODE}); set_csrf_cookie(resp, csrf); return resp
        if not validar_csrf(request, csrf_form): return _error("Token de seguridad inválido. Recarga la página.")
        if not diagnostico or not tratamiento: return _error("Completa el diagnóstico y el tratamiento.")
        if not contrasena_firma: return _error("La contraseña es necesaria para firmar la nota.")
        ruta_llave = LLAVES_DIR / f"personal_{usuario['sub']}.pem"
        try: llave_privada = cargar_privada(ruta_llave, contrasena_firma)
        except Exception: return _error("Contraseña incorrecta. La nota no fue firmada.")
        fecha = _iso_utc(); contenido = canonicalizar_nota(paciente_id, usuario["sub"], diagnostico, tratamiento, fecha); h_bytes = hash_de_contenido(contenido); hash_registro = h_bytes.hex(); firma_b64 = firmar_nota(llave_privada, h_bytes); del llave_privada
        nota = NotaClinica(id=str(uuid.uuid4()), paciente_id=paciente_id, personal_id=usuario["sub"], diagnostico=diagnostico, tratamiento=tratamiento, fecha=fecha, hash_registro=hash_registro, firma_digital=firma_b64)
        Fabrica(con).servicio_clinico().crear_nota(nota, personal_id=usuario["sub"], ip=_ip(request))
        return RedirectResponse(url=f"/pacientes/{paciente_id}", status_code=303)

    @router.get("/pacientes/{paciente_id}/pdf", response_class=HTMLResponse)
    async def historial_pdf(request: Request, paciente_id: str, con=Depends(dep_conexion), usuario: dict = Depends(usuario_actual)):
        if not _puede_ver_expedientes(usuario): return _denegar_acceso(con, usuario, f"/pacientes/{paciente_id}/pdf", _ip(request))
        from app.datos.repo_pacientes import RepoPacientes
        from app.clinico.modelos import Paciente
        pac_dict = RepoPacientes(con).obtener_por_id(paciente_id)
        if pac_dict is None: return RedirectResponse(url="/pacientes", status_code=303)
        fab = Fabrica(con)
        try: paciente, notas = fab.servicio_clinico().obtener_historial(paciente_id, usuario["sub"], _ip(request))
        except Exception:
            paciente = Paciente(**{k: pac_dict[k] for k in ("id", "nombre", "fecha_nacimiento", "contacto")}); notas = []
        return plantillas.TemplateResponse(request, "historial_pdf.html", {"usuario": usuario, "paciente": paciente, "notas": notas, "demo_mode": DEMO_MODE, "csrf_token": ""})

    return router
