"""
Repositorio de personal — único punto de acceso SQL para la tabla `personal`.
Recibe la conexión inyectada por la Factory (DIP).
"""
import sqlite3


class RepoPersonal:
    def __init__(self, conexion: sqlite3.Connection) -> None:
        self._con = conexion

    def obtener_por_email(self, email: str) -> dict | None:
        fila = self._con.execute(
            "SELECT * FROM personal WHERE email = ? AND activo = 1",
            (email,),
        ).fetchone()
        return dict(fila) if fila else None


    def obtener_por_email_incluyendo_inactivos(self, email: str) -> dict | None:
        fila = self._con.execute(
            "SELECT * FROM personal WHERE email = ?",
            (email,),
        ).fetchone()
        return dict(fila) if fila else None

    def obtener_por_id(self, id: str) -> dict | None:
        fila = self._con.execute(
            "SELECT * FROM personal WHERE id = ? AND activo = 1",
            (id,),
        ).fetchone()
        return dict(fila) if fila else None

    def obtener_por_id_incluyendo_inactivos(self, id: str) -> dict | None:
        fila = self._con.execute(
            "SELECT * FROM personal WHERE id = ?",
            (id,),
        ).fetchone()
        return dict(fila) if fila else None

    def listar_todos(self) -> list[dict]:
        filas = self._con.execute(
            "SELECT * FROM personal WHERE activo = 1 ORDER BY nombre"
        ).fetchall()
        return [dict(f) for f in filas]

    def listar_todos_incluyendo_inactivos(self) -> list[dict]:
        filas = self._con.execute(
            "SELECT * FROM personal ORDER BY activo DESC, nombre"
        ).fetchall()
        return [dict(f) for f in filas]
