"""
Script de inicialización de la base de datos.

Uso:  python -m db.semilla

Idempotente: borra la BD existente, recrea el esquema, genera llaves y
llena las tablas con datos de prueba coherentes (hash chain incluida).

Al terminar imprime una contraseña efímera de demostración y guarda los QR
TOTP en llaves/qr_<usuario>.png. Ninguna credencial queda versionada.
"""
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

sys.path.insert(0, str(Path(__file__).parent.parent))

import pyotp
import qrcode
from argon2 import PasswordHasher

from app.config import DB_PATH, ESQUEMA_SQL_PATH, LLAVES_DIR, LLAVE_SERVIDOR_PRIVADA, LLAVE_SERVIDOR_PUBLICA, SECRET_KEY
from app.seguridad.cadena_hash import calcular_hash
from app.seguridad.firma import canonicalizar_nota, hash_de_contenido, firmar_nota
from app.seguridad.llaves import generar_par_rsa, serializar_publica, guardar_privada_cifrada, guardar_publica
from app.seguridad.secretos import cifrar_secreto

CONTRASENA_DEMO = os.getenv("DEMO_PASSWORD", "").strip() or secrets.token_urlsafe(14)
ISSUER_TOTP = "Sistema Seguro: Hospital"
HASH_GENESIS = "0" * 64


def _ahora_utc(delta_dias: int = 0, delta_horas: int = 0) -> str:
    t = datetime.now(timezone.utc) + timedelta(days=delta_dias, hours=delta_horas)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _insertar_audit(con: sqlite3.Connection, hash_prev: str, personal_id: str | None, entidad_afectada: str, entidad_id: str | None, accion: str, detalle: str | None, fecha_hora: str) -> str:
    entrada_id = str(uuid.uuid4())
    hash_actual = calcular_hash(hash_prev, entrada_id, personal_id, entidad_afectada, entidad_id or "", accion, detalle or "", "127.0.0.1", fecha_hora)
    con.execute("""INSERT INTO audit_log (id, personal_id, entidad_afectada, entidad_id, accion, detalle, ip_origen, fecha_hora, hash_anterior, hash_actual) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (entrada_id, personal_id, entidad_afectada, entidad_id, accion, detalle, "127.0.0.1", fecha_hora, hash_prev, hash_actual))
    return hash_actual


def main() -> None:
    LLAVES_DIR.mkdir(exist_ok=True)
    DB_PATH.unlink(missing_ok=True)
    con = sqlite3.connect(str(DB_PATH)); con.execute("PRAGMA foreign_keys = ON"); con.executescript(ESQUEMA_SQL_PATH.read_text(encoding="utf-8")); con.commit()
    print("✓ Base de datos creada desde esquema.sql")

    srv_priv, srv_pub = generar_par_rsa()
    guardar_privada_cifrada(srv_priv, LLAVE_SERVIDOR_PRIVADA, SECRET_KEY)
    guardar_publica(srv_pub, LLAVE_SERVIDOR_PUBLICA)
    print("✓ Llaves del servidor generadas")

    ph = PasswordHasher()
    personal = [
        {"email":"admin@hospital.test","nombre":"Admin Sistema","rol":"admin","especialidad":None},
        {"email":"laura.mendez@hospital.test","nombre":"Dra. Laura Méndez García","rol":"doctor","especialidad":"Cardiología"},
        {"email":"carlos.rios@hospital.test","nombre":"Dr. Carlos Ríos Morales","rol":"doctor","especialidad":"Medicina General"},
        {"email":"ana.torres@hospital.test","nombre":"Enf. Ana Torres Vega","rol":"enfermero","especialidad":None},
    ]
    personal_ids: dict[str,str] = {}; llaves_privadas: dict[str,object] = {}
    print("\n--- Personal creado ---")
    for p in personal:
        uid=str(uuid.uuid4()); personal_ids[p["email"]]=uid
        priv,pub=generar_par_rsa(); llaves_privadas[p["email"]]=priv
        nombre_archivo=p["email"].replace("@","_").replace(".","_")
        guardar_privada_cifrada(priv, LLAVES_DIR / f"personal_{uid}.pem", CONTRASENA_DEMO)
        mfa_secret=pyotp.random_base32(); uri=pyotp.TOTP(mfa_secret).provisioning_uri(p["email"], issuer_name=ISSUER_TOTP)
        qrcode.make(uri).save(str(LLAVES_DIR / f"qr_{nombre_archivo}.png"))
        con.execute("""INSERT INTO personal (id,nombre,rol,especialidad,email,password_hash,mfa_secret,llave_publica,activo) VALUES (?,?,?,?,?,?,?,?,1)""", (uid,p["nombre"],p["rol"],p["especialidad"],p["email"],ph.hash(CONTRASENA_DEMO),cifrar_secreto(mfa_secret),serializar_publica(pub)))
        print(f"  {p['email']}"); print(f"    ID:  {uid}"); print(f"    QR:  llaves/qr_{nombre_archivo}.png")
    con.commit()

    pacientes=[("Juan García López","1985-03-15","555-1001"),("María Rodríguez Pérez","1990-07-22","555-1002"),("Roberto Hernández Silva","1975-11-08","555-1003"),("Carmen López Martínez","2000-01-30","555-1004")]
    paciente_ids=[]
    for nombre,nacimiento,contacto in pacientes:
        pid=str(uuid.uuid4()); paciente_ids.append(pid); con.execute("INSERT INTO pacientes (id,nombre,fecha_nacimiento,contacto) VALUES (?,?,?,?)",(pid,nombre,nacimiento,contacto))
    con.commit()
    juan_id,maria_id,roberto_id,carmen_id=paciente_ids
    laura_id=personal_ids["laura.mendez@hospital.test"]; carlos_id=personal_ids["carlos.rios@hospital.test"]

    citas=[(juan_id,laura_id,_ahora_utc(-60),"agendada",0),(maria_id,carlos_id,_ahora_utc(-45),"atendida",0),(roberto_id,laura_id,_ahora_utc(-30),"cancelada",0),(carmen_id,carlos_id,_ahora_utc(-10),"atendida",1)]
    for pac_id,per_id,fecha,estado,emergencia in citas:
        con.execute("INSERT INTO citas (id,paciente_id,personal_id,fecha,estado,es_emergencia) VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),pac_id,per_id,fecha,estado,emergencia))
    con.commit()

    notas_raw=[
        ("laura.mendez@hospital.test",juan_id,"Hipertensión arterial grado I","Losartán 50 mg/día, dieta baja en sodio",-180),
        ("carlos.rios@hospital.test",maria_id,"Infección respiratoria superior","Amoxicilina 500 mg cada 8 h por 7 días",-150),
        ("laura.mendez@hospital.test",roberto_id,"Diabetes mellitus tipo 2","Metformina 850 mg dos veces al día",-120),
        ("carlos.rios@hospital.test",carmen_id,"Gastroenteritis aguda","Suero oral, dieta blanda por 48 h",-90),
        ("laura.mendez@hospital.test",juan_id,"Control hipertensión — evolución favorable","Continuar Losartán, agregar amlodipino 5 mg",-45),
        ("carlos.rios@hospital.test",maria_id,"Cefalea tensional recurrente","Ibuprofeno 400 mg PRN, técnicas de relajación",-15),
    ]
    hash_prev=HASH_GENESIS
    print("\n--- Notas clínicas firmadas ---")
    for medico_email,pac_id,diagnostico,tratamiento,delta in notas_raw:
        nota_id=str(uuid.uuid4()); med_id=personal_ids[medico_email]; fecha=_ahora_utc(delta)
        contenido=canonicalizar_nota(pac_id,med_id,diagnostico,tratamiento,fecha); h_bytes=hash_de_contenido(contenido); hash_registro=h_bytes.hex(); firma_b64=firmar_nota(llaves_privadas[medico_email],h_bytes)
        con.execute("""INSERT INTO historial_clinico (id,paciente_id,personal_id,diagnostico,tratamiento,fecha,hash_registro,firma_digital) VALUES (?,?,?,?,?,?,?,?)""",(nota_id,pac_id,med_id,diagnostico,tratamiento,fecha,hash_registro,firma_b64))
        hash_prev=_insertar_audit(con,hash_prev,med_id,"historial_clinico",nota_id,"CREAR_NOTA",f"Nota para paciente {pac_id[:8]}...",fecha)
        print(f"  [{medico_email.split('.')[0]}] {diagnostico[:45]}...")
    con.commit(); con.close()

    print(f"""
========================================================
  SEMILLA COMPLETADA
========================================================
  Contraseña de todos los usuarios: {CONTRASENA_DEMO}
  QR codes guardados en:            llaves/qr_*.png
  (En modo demo: /demo/codigos muestra el TOTP vigente)

  Usuarios:
    admin@hospital.test          — Administrador del sistema
    laura.mendez@hospital.test   — Doctora, Cardiología
    carlos.rios@hospital.test    — Doctor, Medicina General
    ana.torres@hospital.test     — Enfermera

  Pacientes: {len(pacientes)}
  Notas clínicas: {len(notas_raw)} (firmadas y verificables)
  Bitácora: {len(notas_raw)} entradas encadenadas desde génesis
========================================================
""")

if __name__ == "__main__":
    main()
