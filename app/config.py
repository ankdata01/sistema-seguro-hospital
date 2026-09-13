"""Configuración centralizada y segura por defecto.

La aplicación no incluye secretos de desarrollo embebidos. Los valores sensibles
se inyectan por variables de entorno y el arranque falla si faltan requisitos
mínimos de seguridad.
"""
from pathlib import Path
import os

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "db" / "clinica.db"
ESQUEMA_SQL_PATH = BASE_DIR / "db" / "esquema.sql"
LLAVES_DIR = BASE_DIR / "llaves"
PLANTILLAS_DIR = Path(__file__).parent / "plantillas"
ESTATICOS_DIR = Path(__file__).parent / "estaticos"

LLAVE_SERVIDOR_PRIVADA = LLAVES_DIR / "servidor_privada.pem"
LLAVE_SERVIDOR_PUBLICA = LLAVES_DIR / "servidor_publica.pem"


def _bool_env(nombre: str, default: bool) -> bool:
    valor = os.getenv(nombre)
    if valor is None:
        return default
    return valor.strip().lower() in {"1", "true", "yes", "on"}


APP_ENV = os.getenv("APP_ENV", "production").strip().lower()
DEMO_MODE = _bool_env("DEMO_MODE", False)
DEMO_TOTP_VIEWER = _bool_env("DEMO_TOTP_VIEWER", False)
COOKIE_SECURE = _bool_env("COOKIE_SECURE", True)
HTTPS_ONLY = _bool_env("HTTPS_ONLY", COOKIE_SECURE)

JWT_ALGORITMO = "RS256"
JWT_EXPIRACION_MINUTOS = 30
JWT_ISSUER = "sistema-seguro-hospital"
JWT_AUDIENCE = "sistema-seguro-hospital-web"

COOKIE_PREFACTOR_NOMBRE = "pre_auth"
COOKIE_PREFACTOR_SEGUNDOS = 300
COOKIE_TOKEN_NOMBRE = "token"

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY es obligatorio y debe tener al menos 32 caracteres. "
        "Genere uno efímero con: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )
