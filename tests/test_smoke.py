"""Pruebas de integración/destructivas para la demo local.

Ejecutar desde la raíz del proyecto:
    python -m pytest -q

Cada prueba que toca datos vuelve a ejecutar db.semilla, por lo que NO debe
usarse contra una base con información que se quiera conservar.
"""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from app.config import DB_PATH, LLAVE_SERVIDOR_PRIVADA
from app.datos.conexion import obtener_conexion
from app.autenticacion import mfa
from app.datos.repo_auditoria import RepoAuditoria
from app.fabrica import Fabrica
from app.main import app
from app.seguridad import rate_limiter as rl
from db.semilla import main as reseed, CONTRASENA_DEMO


def _row(sql: str, args=()):
    con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row
    try:
        fila = con.execute(sql, args).fetchone(); return dict(fila) if fila else None
    finally: con.close()


def _login(email: str) -> TestClient:
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/login").status_code == 200
    csrf = client.cookies["csrf_token"]
    r = client.post("/login", data={"email": email, "contrasena": CONTRASENA_DEMO, "csrf_token": csrf}, follow_redirects=False)
    assert (r.status_code, r.headers.get("location")) == (303, "/login/mfa")
    assert client.get("/login/mfa").status_code == 200
    csrf = client.cookies["csrf_token"]
    secret = _row("SELECT mfa_secret FROM personal WHERE email = ?", (email,))["mfa_secret"]
    codigo = mfa.codigo_actual(secret)
    r = client.post("/login/mfa", data={"codigo": codigo, "csrf_token": csrf}, follow_redirects=False)
    assert (r.status_code, r.headers.get("location")) == (303, "/panel")
    assert client.cookies.get("token")
    return client


def test_semilla_e_integridad_inicial():
    reseed(); con = obtener_conexion()
    try:
        resultado = Fabrica(con).ejecutar_verificacion(); assert resultado["todo_ok"] is True; assert resultado["cadena"]["total"] == 6; assert resultado["firmas_invalidas"] == []
    finally: con.close()


def test_matriz_de_autorizacion_clave():
    reseed(); enfermera = _login("ana.torres@hospital.test")
    assert enfermera.get("/pacientes", follow_redirects=False).status_code == 200
    for ruta in ("/auditoria", "/sesiones", "/auditoria/exportar.csv"):
        r = enfermera.get(ruta, follow_redirects=False); assert r.status_code == 303; assert r.headers["location"].startswith("/panel?error=acceso_denegado")
    admin = _login("admin@hospital.test"); r = admin.get("/pacientes", follow_redirects=False); assert r.status_code == 303; assert r.headers["location"].startswith("/panel?error=acceso_denegado"); assert admin.get("/auditoria", follow_redirects=False).status_code == 200


def test_logout_requiere_csrf():
    reseed(); client = _login("laura.mendez@hospital.test"); assert client.cookies.get("token")
    r = client.post("/logout", follow_redirects=False); assert r.status_code == 303; assert r.headers["location"] == "/panel?error=csrf"; assert client.cookies.get("token")
    assert client.get("/panel").status_code == 200; csrf = client.cookies["csrf_token"]
    r = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False); assert r.status_code == 303; assert r.headers["location"] == "/login"; assert not client.cookies.get("token")


def test_rate_limit_bloquea_quince_minutos():
    rl._intentos.clear(); rl._bloqueado_hasta.clear()
    for _ in range(rl.MAX_INTENTOS): rl.registrar_fallo("prueba")
    assert rl.esta_bloqueado("prueba"); assert 895 <= rl.segundos_restantes("prueba") <= rl.BLOQUEO_SEG


def test_escrituras_auditoria_concurrentes_mantienen_cadena():
    reseed()
    def escribir(i: int):
        con = obtener_conexion()
        try: RepoAuditoria(con).insertar_encadenado(personal_id=None, entidad_afectada="test", entidad_id=str(i), accion="CONCURRENCIA", detalle=f"writer={i}", ip_origen="127.0.0.1")
        finally: con.close()
    with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(escribir, range(20)))
    con = obtener_conexion()
    try:
        cadena = Fabrica(con).ejecutar_verificacion()["cadena"]; assert cadena["integra"] is True; assert cadena["total"] == 26
    finally: con.close()


def test_verificador_detecta_hash_anterior_manipulado():
    reseed(); con = sqlite3.connect(DB_PATH)
    try:
        con.execute("DROP TRIGGER audit_log_no_update"); entrada_id = con.execute("SELECT id FROM audit_log ORDER BY rowid LIMIT 1").fetchone()[0]; con.execute("UPDATE audit_log SET hash_anterior = ? WHERE id = ?", ("f" * 64, entrada_id)); con.commit()
    finally: con.close()
    con = obtener_conexion()
    try:
        cadena = Fabrica(con).ejecutar_verificacion()["cadena"]; assert cadena["integra"] is False; assert cadena["primera_fila_rota"] == entrada_id
    finally: con.close()


def test_restaurar_invalida_sesion_anterior():
    reseed(); client = _login("laura.mendez@hospital.test"); assert client.get("/demo").status_code == 200; csrf = client.cookies["csrf_token"]
    r = client.post("/demo/restaurar", data={"csrf_token": csrf}, follow_redirects=False); assert r.status_code == 303; assert r.headers["location"] == "/login?restaurado=ok"; assert not client.cookies.get("token")


def test_secretos_sensibles_cifrados_en_reposo():
    reseed(); secret = _row("SELECT mfa_secret FROM personal WHERE email = ?", ("laura.mendez@hospital.test",))["mfa_secret"]; assert secret.startswith("enc:v1:")
    pem = LLAVE_SERVIDOR_PRIVADA.read_text(encoding="utf-8"); assert "ENCRYPTED" in pem


def test_cambio_de_ip_en_bitacora_rompe_integridad():
    reseed(); con = sqlite3.connect(DB_PATH)
    try:
        con.execute("DROP TRIGGER audit_log_no_update"); entrada_id = con.execute("SELECT id FROM audit_log ORDER BY rowid LIMIT 1").fetchone()[0]; con.execute("UPDATE audit_log SET ip_origen = ? WHERE id = ?", ("203.0.113.77", entrada_id)); con.commit()
    finally: con.close()
    con = obtener_conexion()
    try:
        cadena = Fabrica(con).ejecutar_verificacion()["cadena"]; assert cadena["integra"] is False; assert cadena["primera_fila_rota"] == entrada_id
    finally: con.close()


def test_usuario_desactivado_pierde_sesion_inmediatamente():
    reseed(); client = _login("laura.mendez@hospital.test"); assert client.get("/panel", follow_redirects=False).status_code == 200
    con = sqlite3.connect(DB_PATH)
    try: con.execute("UPDATE personal SET activo = 0 WHERE email = ?", ("laura.mendez@hospital.test",)); con.commit()
    finally: con.close()
    r = client.get("/panel", follow_redirects=False); assert r.status_code == 303; assert r.headers["location"] == "/login"


def test_cabeceras_de_seguridad_y_visores_demo_restringidos():
    reseed(); client = TestClient(app, raise_server_exceptions=False); r = client.get("/login")
    assert r.status_code == 200; assert r.headers["x-content-type-options"] == "nosniff"; assert r.headers["x-frame-options"] == "DENY"; assert "frame-ancestors 'none'" in r.headers["content-security-policy"]; assert r.headers["cache-control"] == "no-store"
    r = client.get("/demo/codigos", follow_redirects=False); assert r.status_code == 404


def test_desactivar_medico_no_invalida_firmas_historicas():
    reseed(); con = sqlite3.connect(DB_PATH)
    try: con.execute("UPDATE personal SET activo = 0 WHERE email = ?", ("laura.mendez@hospital.test",)); con.commit()
    finally: con.close()
    con = obtener_conexion()
    try: assert Fabrica(con).ejecutar_verificacion()["firmas_invalidas"] == []
    finally: con.close()
