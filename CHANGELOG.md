# Changelog

## 1.1.0 — 2026-09-13

### Seguridad
- `DEMO_MODE` ahora es `false` por defecto.
- Eliminado el fallback de `SECRET_KEY`; el arranque falla con menos de 32 caracteres.
- TOTP cifrado en SQLite mediante AES-256-GCM con clave derivada por HKDF-SHA256.
- Llave privada JWT almacenada cifrada en PEM; permisos `0600` cuando el SO lo permite.
- Cookies de sesión, preautenticación y CSRF con endurecimiento configurable `Secure` y `SameSite=Strict`.
- Middleware de CSP, HSTS configurable, anti-framing, `nosniff`, `Referrer-Policy`, `Permissions-Policy` y `no-store`.
- JWT valida `iss`, `aud`, `nbf`, `exp` y claims obligatorios.
- Cada petición autenticada revalida que la cuenta siga activa y conserve el rol emitido.
- La cadena de auditoría incorpora `ip_origen` y usa delimitador canónico.
- `PASSWORD_OK` y `LOGIN_OK` separan primer factor de autenticación completa.
- Accesos denegados a administración/auditoría/demo quedan auditados.
- Panel de ataque demo limitado a doctor/admin.
- Visor TOTP deshabilitado por defecto y restringido a loopback.
- Contraseñas de semilla dejan de estar codificadas en el repositorio; se generan o inyectan por entorno.
- Contraseñas de alta no se vuelven a mostrar después del POST; mínimo 12 caracteres.
- Verificación de firmas históricas conserva validez aunque el firmante esté inactivo.

### Repositorio y documentación
- Añadidos STRIDE, MITRE ATT&CK, X.800 y Defense in Depth.
- Añadidos `SECURITY.md`, `docs/informe-final.md` y carpeta `evidencias/`.
- CI genera secretos efímeros; no contiene claves estáticas.
- Suite ampliada a 12 pruebas de integración/seguridad.

## 1.0.0
- Versión base de demostración con MFA, RSA-PSS, cadena de hashes, RBAC y pruebas smoke.
