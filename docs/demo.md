# Guion técnico de demostración v1.1.0

## Preparación

```powershell
$PY = "python"
$env:DEMO_MODE = "true"
$env:DEMO_TOTP_VIEWER = "true"   # opcional y solo loopback
$env:COOKIE_SECURE = "false"
$env:HTTPS_ONLY = "false"
$env:SECRET_KEY = & $PY -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DEMO_PASSWORD = & $PY -c "import secrets; print(secrets.token_urlsafe(18))"
$env:DEMO_PASSWORD

& $PY -m db.semilla
& $PY -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Usuarios de prueba: `admin@clinica.mx`, `laura.mendez@clinica.mx`, `carlos.rios@clinica.mx`, `ana.torres@clinica.mx`. La contraseña es el valor efímero de `DEMO_PASSWORD` de la sesión.

## Secuencia de 10–12 minutos

1. **Autenticidad:** ingresar como doctora; demostrar que contraseña solo genera preautenticación y que TOTP completa el login.
2. **Sesión segura:** mostrar en auditoría `PASSWORD_OK` seguido de `LOGIN_OK`.
3. **No repudio:** abrir paciente, crear nota y volver a ingresar la contraseña para descifrar la llave privada y firmar RSA-PSS.
4. **Integridad:** mostrar hash SHA-256 y firma digital.
5. **Manipulación:** `/demo` → ejecutar UPDATE directo. Solo doctor/admin puede usar estas rutas.
6. **Detección:** Auditoría → verificar integridad; mostrar `contenido_alterado`.
7. **Trazabilidad:** intentar DELETE de `audit_log`; el trigger debe rechazarlo y el intento queda auditado.
8. **Defense in Depth:** mencionar CSP/cookies/RBAC/cifrado TOTP/PEM/CI además de los tres controles principales.

## Restauración

El botón de restauración exige que `DEMO_PASSWORD` esté definido en el entorno; así la semilla conserva la contraseña durante la presentación. Al restaurar se regeneran UUID, llaves y TOTP, y la sesión actual se invalida.

## Regla operativa

No usar `--host 0.0.0.0` con `DEMO_TOTP_VIEWER=true`. Para una demostración compartida por LAN, deshabilite el visor TOTP y use un autenticador real.
