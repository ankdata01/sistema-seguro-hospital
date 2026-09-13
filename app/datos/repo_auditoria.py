"""
Repositorio de auditoría — único punto de acceso SQL para `audit_log`.

`insertar_encadenado()` serializa escritores con BEGIN IMMEDIATE, obtiene el
último hash y calcula/inserta el siguiente eslabón dentro de la misma
transacción. Esto evita el TOCTOU que rompería la cadena si dos peticiones
intentaran auditar simultáneamente.
"""
import sqlite3
import uuid
from datetime import datetime, timezone

from app.seguridad.cadena_hash import calcular_hash

HASH_GENESIS = "0" * 64


class RepoAuditoria:
    def __init__(self, conexion: sqlite3.Connection) -> None:
        self._con = conexion

    def obtener_ultimo_hash(self) -> str:
        """Devuelve el hash_actual del último eslabón insertado, o génesis."""
        fila = self._con.execute(
            "SELECT hash_actual FROM audit_log ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return fila["hash_actual"] if fila else HASH_GENESIS

    def insertar_encadenado(
        self,
        *,
        personal_id: str | None,
        entidad_afectada: str,
        entidad_id: str | None,
        accion: str,
        detalle: str | None,
        ip_origen: str | None,
        fecha_hora: str | None = None,
    ) -> dict:
        """Crea el siguiente eslabón de la bitácora de forma transaccional."""
        if fecha_hora is None:
            fecha_hora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        entrada_id = str(uuid.uuid4())
        try:
            self._con.execute("BEGIN IMMEDIATE")
            fila = self._con.execute(
                "SELECT hash_actual FROM audit_log ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            hash_anterior = fila["hash_actual"] if fila else HASH_GENESIS
            hash_actual = calcular_hash(
                hash_anterior,
                entrada_id,
                personal_id,
                entidad_afectada,
                entidad_id or "",
                accion,
                detalle or "",
                ip_origen or "",
                fecha_hora,
            )
            self._con.execute(
                """INSERT INTO audit_log
                   (id, personal_id, entidad_afectada, entidad_id, accion,
                    detalle, ip_origen, fecha_hora, hash_anterior, hash_actual)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entrada_id,
                    personal_id,
                    entidad_afectada,
                    entidad_id,
                    accion,
                    detalle,
                    ip_origen,
                    fecha_hora,
                    hash_anterior,
                    hash_actual,
                ),
            )
            self._con.commit()
        except Exception:
            self._con.rollback()
            raise

        return {
            "id": entrada_id,
            "personal_id": personal_id,
            "entidad_afectada": entidad_afectada,
            "entidad_id": entidad_id,
            "accion": accion,
            "detalle": detalle,
            "ip_origen": ip_origen,
            "fecha_hora": fecha_hora,
            "hash_anterior": hash_anterior,
            "hash_actual": hash_actual,
        }

    def insertar(self, entrada: dict) -> None:
        """Inserta una entrada ya encadenada. Uso interno/compatibilidad."""
        self._con.execute(
            """INSERT INTO audit_log
               (id, personal_id, entidad_afectada, entidad_id, accion,
                detalle, ip_origen, fecha_hora, hash_anterior, hash_actual)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entrada["id"],
                entrada.get("personal_id"),
                entrada["entidad_afectada"],
                entrada.get("entidad_id"),
                entrada["accion"],
                entrada.get("detalle"),
                entrada.get("ip_origen"),
                entrada["fecha_hora"],
                entrada["hash_anterior"],
                entrada["hash_actual"],
            ),
        )
        self._con.commit()

    def listar_todos(self) -> list[dict]:
        filas = self._con.execute(
            "SELECT * FROM audit_log ORDER BY rowid"
        ).fetchall()
        return [dict(f) for f in filas]

    def listar_recientes(self, limite: int = 100) -> list[dict]:
        filas = self._con.execute(
            "SELECT * FROM audit_log ORDER BY rowid DESC LIMIT ?",
            (limite,),
        ).fetchall()
        return [dict(f) for f in filas]
