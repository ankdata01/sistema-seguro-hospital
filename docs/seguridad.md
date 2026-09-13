# Seguridad implementada — v1.1.0

## Identidad y sesión

- Argon2id para hashes de contraseña.
- TOTP RFC 6238 como segundo factor.
- Secreto TOTP cifrado con AES-256-GCM y HKDF-SHA256.
- JWT RS256 con `sub`, `rol`, `iss`, `aud`, `iat`, `nbf`, `exp` y `jti`.
- Llave privada JWT guardada cifrada en PEM.
- Cada petición protegida revalida usuario activo y rol.
- Cookies HttpOnly, SameSite=Strict y `Secure` configurable; CSRF double-submit.

## Autorización

- Doctor: consulta y firma notas.
- Enfermero: consulta.
- Administrativo: consulta y auditoría.
- Admin: usuarios y auditoría.
- Demo destructiva: doctor/admin.
- Denegaciones relevantes se registran como `ACCESO_DENEGADO`.

## Integridad y no repudio

Cada nota se canonicaliza, resume con SHA-256 y firma mediante RSA-PSS con la llave privada del médico. La llave privada personal está cifrada con su contraseña. La verificación usa la llave pública aunque la cuenta del médico esté inactiva.

## Trazabilidad

La bitácora encadena `hash_anterior`, id, usuario, entidad, acción, detalle, `ip_origen` y timestamp. Las inserciones se serializan con `BEGIN IMMEDIATE`. Triggers rechazan UPDATE y DELETE. El verificador recalcula todos los eslabones.

## Aplicación web

SQL parametrizado, autoescape de Jinja2, Swagger/ReDoc deshabilitados, CSP, anti-framing, `nosniff`, Referrer-Policy, Permissions-Policy, HSTS cuando corresponde y `Cache-Control: no-store` para contenido dinámico.

## Limitaciones

La seguridad de aplicación no protege contra control total del host. SQLite y archivos locales no sustituyen WORM, SIEM, KMS/HSM, alta disponibilidad ni cifrado integral de base de datos. El prototipo no declara cumplimiento regulatorio.
