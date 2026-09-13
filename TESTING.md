# Pruebas y validación — Clínica Segura v1.1.0

## 1. Preparación

La configuración es segura por defecto y no arranca con un secreto embebido. En PowerShell:

```powershell
$PY = "python"
$env:DEMO_MODE = "true"
$env:DEMO_TOTP_VIEWER = "false"
$env:COOKIE_SECURE = "false"
$env:HTTPS_ONLY = "false"
$env:SECRET_KEY = & $PY -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DEMO_PASSWORD = & $PY -c "import secrets; print(secrets.token_urlsafe(18))"

& $PY -m pip install -r requirements-dev.txt
```

`COOKIE_SECURE=false` y `HTTPS_ONLY=false` son exclusivamente para `http://127.0.0.1`. Con HTTPS deben permanecer en `true`.

## 2. Suite automatizada

```powershell
& $PY -m pytest -q
```

La suite verifica:

1. semilla e integridad inicial de firmas y cadena;
2. MFA y emisión de JWT;
3. autorización RBAC en expedientes/auditoría;
4. CSRF en logout;
5. rate limiting de quince minutos tras cinco fallos;
6. 20 escrituras concurrentes de auditoría sin romper la cadena;
7. detección de manipulación de `hash_anterior`;
8. restauración e invalidación de sesión anterior;
9. TOTP cifrado y PEM privado JWT cifrado en reposo;
10. detección de modificación de `ip_origen` en auditoría;
11. invalidación inmediata de sesión al desactivar una cuenta;
12. cabeceras HTTP y visor TOTP deshabilitado por defecto;
13. verificación de firmas históricas aunque el médico quede inactivo.

> El archivo contiene 12 funciones de prueba; algunas funciones validan más de un control.

## 3. Pruebas manuales recomendadas

### Login y MFA

- contraseña correcta sin TOTP: no debe existir sesión completa;
- TOTP inválido repetido: debe activar rate limiting;
- TOTP válido: debe aparecer `LOGIN_OK` tras `PASSWORD_OK`.

### Integridad

- crear nota como doctor;
- ejecutar `/demo/atacar`;
- verificar auditoría: debe reportar `contenido_alterado`;
- intentar DELETE de `audit_log`: trigger debe abortar;
- alterar `ip_origen` tras deshabilitar el trigger en un entorno de prueba: la cadena debe fallar.

### Autorización

- enfermero: puede consultar expedientes, no auditoría ni creación de notas;
- administrativo: consulta + auditoría, no firma;
- admin: gestión + auditoría, no expediente clínico;
- usuario desactivado: su sesión existente debe redirigir a login.

## 4. Validación estática mínima

```powershell
& $PY -m compileall -q app db tests
```

Antes de publicar GitHub:

```powershell
git status --ignored
```

Confirme que `db/clinica.db`, `llaves/`, `.env` y cualquier export de auditoría no estén versionados. Se recomienda además un escáner especializado de secretos en CI.

## 5. Evidencia

Los resultados de la revisión incluida con esta entrega están en `evidencias/resultado-validacion.txt`. El CI de GitHub genera `SECRET_KEY` y `DEMO_PASSWORD` de forma efímera en cada ejecución; no hay valores secretos estáticos en el workflow.
