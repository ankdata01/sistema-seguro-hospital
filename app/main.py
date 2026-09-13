"""
Punto de entrada de FastAPI.
Monta archivos estáticos, configura Jinja2 y registra los routers de cada capa.
No contiene lógica de negocio ni seguridad: solo ensambla la aplicación.
"""
from fastapi import FastAPI, Depends, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import ESTATICOS_DIR, PLANTILLAS_DIR, DEMO_MODE
from app.seguridad.headers import SecurityHeadersMiddleware
from app.presentacion.dependencias import (
    NoAutenticado, usuario_actual, dep_conexion,
    generar_csrf, set_csrf_cookie,
)

# ---------------------------------------------------------------------------
# Instancia principal
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Clínica Segura",
    description="Expediente clínico con autenticidad, no repudio y trazabilidad.",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(SecurityHeadersMiddleware)

app.mount(
    "/estaticos",
    StaticFiles(directory=str(ESTATICOS_DIR)),
    name="estaticos",
)

plantillas = Jinja2Templates(directory=str(PLANTILLAS_DIR))

# ---------------------------------------------------------------------------
# Handler global: sesión falta o expiró → login
# ---------------------------------------------------------------------------
@app.exception_handler(NoAutenticado)
async def redirigir_login(request: Request, exc: NoAutenticado):
    return RedirectResponse(url="/login", status_code=303)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
from app.presentacion import rutas_auth, rutas_clinicas, rutas_auditoria, rutas_demo, rutas_admin

app.include_router(rutas_auth.crear_router(plantillas))
app.include_router(rutas_clinicas.crear_router(plantillas))
app.include_router(rutas_auditoria.crear_router(plantillas))
app.include_router(rutas_admin.crear_router(plantillas))

if DEMO_MODE:
    app.include_router(rutas_demo.crear_router(plantillas))

# ---------------------------------------------------------------------------
# Raíz → panel si hay sesión, login si no
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def raiz():
    return RedirectResponse(url="/panel")

# ---------------------------------------------------------------------------
# Panel principal — protegido, muestra estado rápido de la cadena
# ---------------------------------------------------------------------------
@app.get("/panel", response_class=HTMLResponse)
async def panel(
    request: Request,
    con=Depends(dep_conexion),
    usuario: dict = Depends(usuario_actual),
):
    from app.fabrica import Fabrica
    fab = Fabrica(con)
    # Verificación rápida de la cadena para el badge del panel
    from app.seguridad.verificador import verificar_cadena
    estado_cadena = verificar_cadena(fab.repo_auditoria())

    csrf = generar_csrf()
    resp = plantillas.TemplateResponse(
        request, "panel.html",
        {
            "usuario":      usuario,
            "estado_cadena": estado_cadena,
            "csrf_token":   csrf,
            "demo_mode":    DEMO_MODE,
        },
    )
    set_csrf_cookie(resp, csrf)
    return resp
