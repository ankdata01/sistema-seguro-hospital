# Política de seguridad del prototipo

## Principios

1. No usar datos clínicos, contraseñas ni claves reales.
2. No versionar `.env`, `db/hospital.db`, `llaves/*.pem`, QR TOTP ni exports de auditoría.
3. `SECRET_KEY` debe inyectarse por entorno y tener al menos 32 caracteres.
4. `DEMO_MODE` y `DEMO_TOTP_VIEWER` deben permanecer deshabilitados fuera de una demostración controlada.
5. `COOKIE_SECURE=true` y HTTPS son obligatorios en cualquier despliegue no local.

## Rotación

Cambiar `SECRET_KEY` invalida la capacidad de descifrar los secretos TOTP y la llave privada JWT generados con la clave anterior. En esta demo se resuelve ejecutando nuevamente `python -m db.semilla`. En producción se requeriría versionado de claves y un proceso de migración.

## Material sensible generado

`llaves/` y `db/hospital.db` son artefactos locales. El `.gitignore` impide su inclusión normal, pero antes de publicar un repositorio debe ejecutarse una revisión de secretos y comprobar el historial Git.

## Reporte

Este proyecto es académico y no mantiene un programa formal de respuesta a vulnerabilidades. Si se reutiliza, debe agregarse un canal privado de reporte y un SLA de remediación.
