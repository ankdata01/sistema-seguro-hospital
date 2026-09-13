"""Verificación independiente de cadena de auditoría y firmas clínicas."""
from app.datos.repo_auditoria import RepoAuditoria
from app.datos.repo_historial import RepoHistorial
from app.datos.repo_personal import RepoPersonal
from app.seguridad.cadena_hash import calcular_hash
from app.seguridad.firma import canonicalizar_nota, hash_de_contenido, verificar_firma
from app.seguridad.llaves import cargar_publica_desde_pem

HASH_GENESIS = "0" * 64

def verificar_cadena(repo_auditoria: RepoAuditoria) -> dict:
    entradas = repo_auditoria.listar_todos(); hash_anterior = HASH_GENESIS
    for entrada in entradas:
        esperado = calcular_hash(hash_anterior, entrada["id"], entrada["personal_id"], entrada["entidad_afectada"], entrada["entidad_id"] or "", entrada["accion"], entrada["detalle"] or "", entrada["ip_origen"] or "", entrada["fecha_hora"])
        if entrada["hash_anterior"] != hash_anterior or esperado != entrada["hash_actual"]:
            return {"integra": False, "total": len(entradas), "primera_fila_rota": entrada["id"]}
        hash_anterior = entrada["hash_actual"]
    return {"integra": True, "total": len(entradas), "primera_fila_rota": None}

def verificar_firmas(repo_historial: RepoHistorial, repo_personal: RepoPersonal) -> list[dict]:
    problemas=[]
    for fila in repo_historial.obtener_todos():
        personal = repo_personal.obtener_por_id_incluyendo_inactivos(fila["personal_id"])
        if personal is None:
            problemas.append({"id": fila["id"], "motivo": "medico_no_encontrado", "hash_esperado": None, "hash_guardado": fila["hash_registro"]}); continue
        contenido = canonicalizar_nota(fila["paciente_id"], fila["personal_id"], fila["diagnostico"], fila["tratamiento"], fila["fecha"])
        h_bytes = hash_de_contenido(contenido); hash_recalculado = h_bytes.hex()
        if hash_recalculado != fila["hash_registro"]:
            problemas.append({"id": fila["id"], "motivo": "contenido_alterado", "hash_esperado": hash_recalculado, "hash_guardado": fila["hash_registro"]}); continue
        try:
            llave_publica = cargar_publica_desde_pem(personal["llave_publica"]); firma_valida = verificar_firma(llave_publica, h_bytes, fila["firma_digital"])
        except (TypeError, ValueError): firma_valida = False
        if not firma_valida:
            problemas.append({"id": fila["id"], "motivo": "firma_invalida", "hash_esperado": hash_recalculado, "hash_guardado": fila["hash_registro"]})
    return problemas

def verificar_todo(repo_auditoria: RepoAuditoria, repo_historial: RepoHistorial, repo_personal: RepoPersonal) -> dict:
    cadena = verificar_cadena(repo_auditoria); firmas = verificar_firmas(repo_historial, repo_personal)
    return {"cadena": cadena, "firmas_invalidas": firmas, "todo_ok": cadena["integra"] and len(firmas) == 0}
