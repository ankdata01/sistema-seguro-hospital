"""
Servicio de autenticación — orquesta contraseña, TOTP, JWT y auditoría de sesión.

Recibe los repositorios inyectados (nunca los instancia él mismo).
No importa nada de presentación (HTTP, cookies, Jinja2).
"""
from datetime import datetime, timezone

from app.autenticacion import passwords, mfa, tokens
from app.datos.repo_personal import RepoPersonal
from app.datos.repo_auditoria import RepoAuditoria


# ---------------------------------------------------------------------------
# Excepciones de dominio — la capa de presentación las captura y decide
# qué respuesta HTTP mostrar.
# ---------------------------------------------------------------------------
class CredencialesInvalidas(Exception):
    """Correo no existe o contraseña incorrecta."""


class CodigoMFAInvalido(Exception):
    """Código TOTP incorrecto o expirado."""


class UsuarioNoEncontrado(Exception):
    """El user_id del pre-auth cookie no existe en la BD."""


# ---------------------------------------------------------------------------
# Servicio
# ---------------------------------------------------------------------------
class ServicioAuth:
    def __init__(
        self,
        repo_personal: RepoPersonal,
        repo_auditoria: RepoAuditoria,
    ) -> None:
        self._personal = repo_personal
        self._audit = repo_auditoria

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def primer_factor(self, email: str, contrasena: str, ip: str) -> dict:
        """
        Verifica email + contraseña.
        Audita PASSWORD_OK o LOGIN_FALLIDO.
        Devuelve el registro del personal si es correcto.
        Lanza CredencialesInvalidas si falla.
        """
        usuario = self._personal.obtener_por_email(email)
        ahora = self._iso_utc()

        if usuario is None or not passwords.verificar(usuario["password_hash"], contrasena):
            self._auditar(
                personal_id=usuario["id"] if usuario else None,
                entidad_afectada="sesion",
                entidad_id=None,
                accion="LOGIN_FALLIDO",
                detalle=f"Intento para {email}",
                ip=ip,
                fecha_hora=ahora,
            )
            raise CredencialesInvalidas()

        self._auditar(
            personal_id=usuario["id"],
            entidad_afectada="sesion",
            entidad_id=None,
            accion="PASSWORD_OK",
            detalle="Primer factor correcto — esperando MFA",
            ip=ip,
            fecha_hora=ahora,
        )
        return dict(usuario)

    def segundo_factor(self, user_id: str, codigo: str, ip: str) -> str:
        """
        Verifica el código TOTP y emite el JWT.
        Audita MFA_FALLIDO o el acceso definitivo.
        Devuelve el token JWT como cadena.
        Lanza CodigoMFAInvalido o UsuarioNoEncontrado.
        """
        usuario = self._personal.obtener_por_id(user_id)
        if usuario is None:
            raise UsuarioNoEncontrado()

        ahora = self._iso_utc()

        if not mfa.validar_totp(usuario["mfa_secret"], codigo):
            self._auditar(
                personal_id=user_id,
                entidad_afectada="sesion",
                entidad_id=None,
                accion="MFA_FALLIDO",
                detalle="Código TOTP incorrecto",
                ip=ip,
                fecha_hora=ahora,
            )
            raise CodigoMFAInvalido()

        token = tokens.emitir(usuario)
        self._auditar(
            personal_id=user_id,
            entidad_afectada="sesion",
            entidad_id=None,
            accion="LOGIN_OK",
            detalle="MFA correcto; sesión emitida",
            ip=ip,
            fecha_hora=ahora,
        )
        return token

    def registrar_logout(self, user_id: str, ip: str) -> None:
        self._auditar(
            personal_id=user_id,
            entidad_afectada="sesion",
            entidad_id=None,
            accion="LOGOUT",
            detalle=None,
            ip=ip,
            fecha_hora=self._iso_utc(),
        )

    def registrar_acceso_denegado(self, user_id: str, recurso: str, ip: str) -> None:
        self._auditar(
            personal_id=user_id,
            entidad_afectada="sesion",
            entidad_id=None,
            accion="ACCESO_DENEGADO",
            detalle=recurso,
            ip=ip,
            fecha_hora=self._iso_utc(),
        )

    # ------------------------------------------------------------------
    # Helpers privados
    # ------------------------------------------------------------------
    def _auditar(
        self,
        personal_id: str | None,
        entidad_afectada: str,
        entidad_id: str | None,
        accion: str,
        detalle: str | None,
        ip: str,
        fecha_hora: str,
    ) -> None:
        self._audit.insertar_encadenado(
            personal_id=personal_id,
            entidad_afectada=entidad_afectada,
            entidad_id=entidad_id,
            accion=accion,
            detalle=detalle,
            ip_origen=ip,
            fecha_hora=fecha_hora,
        )

    @staticmethod
    def _iso_utc() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
