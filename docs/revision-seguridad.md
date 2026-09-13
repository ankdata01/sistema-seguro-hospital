# Revisión de seguridad v1.1.0

## Correcciones respecto de v1.0.0

| Hallazgo | Corrección |
|---|---|
| Demo habilitada por defecto | `DEMO_MODE=false` |
| Fallback de secreto en código | `SECRET_KEY` obligatorio y validado |
| TOTP en claro en SQLite | AES-256-GCM + HKDF-SHA256 |
| Llave JWT privada en claro | PEM cifrado con `SECRET_KEY` |
| IP de auditoría fuera del hash | `ip_origen` incorporada a la cadena |
| JWT aceptado hasta expirar aunque usuario se desactive | consulta de cuenta activa en cada petición |
| Claims sin issuer/audience | `iss` y `aud` obligatorios |
| Login de primer factor etiquetado como completo | separación `PASSWORD_OK` / `LOGIN_OK` |
| Denegaciones no uniformemente auditadas | administración/auditoría/demo registran `ACCESO_DENEGADO` |
| Visor TOTP expuesto solo por DEMO_MODE | flag separado, default false, loopback-only |
| Contraseña demo fija en repo/README/tests | valor efímero o variable de entorno |
| CI con secreto estático de ejemplo | generación efímera en workflow |
| Contraseña de alta reimpresa en HTML | ya no se devuelve; mínimo 12 caracteres |
| Desactivar médico hacía fallar firma histórica | verificador usa llave pública de cuentas inactivas |
| Falta de cabeceras web | CSP/HSTS/no-store/anti-framing/nosniff |

## Riesgos aceptados

- SQLite local y rate limiter en memoria.
- No hay log remoto/WORM.
- No hay cifrado integral de expediente a nivel de aplicación.
- No hay HSM/KMS/TSA.
- TOTP puede ser objeto de phishing en tiempo real.
- Las operaciones clínica+auditoría no son una transacción distribuida/atómica única.
- El prototipo depende del endurecimiento del host y de TLS externo para un despliegue real.

## Estado

La versión 1.1.0 satisface los requerimientos académicos de documentación, modelado de amenazas, controles implementados, pruebas y evidencia de repositorio. Esto no constituye auditoría formal ni certificación regulatoria.
