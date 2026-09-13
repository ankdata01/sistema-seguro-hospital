"""Cálculo canónico del hash encadenado de auditoría."""
import hashlib


def calcular_hash(hash_anterior: str, id: str, personal_id: str | None, entidad_afectada: str, entidad_id: str | None, accion: str, detalle: str | None, ip_origen: str | None, fecha_hora: str) -> str:
    campos = (hash_anterior, id, personal_id or "", entidad_afectada, entidad_id or "", accion, detalle or "", ip_origen or "", fecha_hora)
    contenido = "\x1f".join(campos)
    return hashlib.sha256(contenido.encode("utf-8")).hexdigest()
