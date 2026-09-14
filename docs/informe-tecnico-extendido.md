# Portada

**SISTEMA SEGURO: HOSPITAL v1.1.0**  
**Diseño e implementación de controles de ciberseguridad para un expediente clínico electrónico**

Proyecto académico de ciberseguridad  
Asignatura: **[Nombre de la asignatura]**  
Institución: **[Nombre de la institución]**  
Autor(es): **[Nombre(s) del estudiante/equipo]**  
Docente: **[Nombre del docente]**  
Fecha: **13 de septiembre de 2026**

**Versión evaluada:** 1.1.0  
**Tecnologías principales:** Python 3.12, FastAPI, Jinja2, SQLite, Argon2id, TOTP, JWT RS256, RSA-PSS, SHA-256 y AES-256-GCM.

> **Nota de alcance.** Sistema Seguro: Hospital es un prototipo académico. Demuestra controles técnicos y un proceso de ingeniería de seguridad, pero no constituye por sí mismo una plataforma clínica certificada ni acredita cumplimiento legal o normativo para expedientes reales.

# Resumen

Sistema Seguro: Hospital v1.1.0 es un prototipo de expediente clínico electrónico diseñado para demostrar de forma verificable autenticidad, integridad, control de acceso, no repudio y trazabilidad. Utiliza autenticación multifactor con Argon2id y TOTP, sesiones JWT RS256, autorización basada en roles, firma RSA-PSS de notas clínicas, hashes SHA-256 y una bitácora encadenada protegida contra modificaciones y eliminaciones por la propia aplicación.

La revisión de esta versión modificó el código para eliminar secretos embebidos, cifrar secretos TOTP en reposo con AES-256-GCM, cifrar la llave privada del servidor, endurecer JWT, revalidar cuentas en cada petición protegida, incluir IP en la cadena de auditoría, fortalecer cookies y cabeceras HTTP, restringir funciones peligrosas de demostración y conservar la verificabilidad de firmas históricas de médicos desactivados.

El análisis usa STRIDE, MITRE ATT&CK, X.800 y Defense in Depth. La validación automatizada consta de doce pruebas de integración y seguridad, compilación estática y revisión de secretos versionables. Las limitaciones productivas —SQLite, rate limiting en memoria, ausencia de HSM/KMS, cifrado integral de BD y log remoto inmutable— se declaran explícitamente.

# Introducción

Los sistemas clínicos requieren proteger identidad, autorización, integridad, autoría, confidencialidad, disponibilidad y auditoría. Un control aislado no cubre todos estos objetivos: una contraseña fuerte no evita la manipulación directa de una base de datos, una firma digital no controla quién puede leer un expediente y una bitácora local no equivale a un registro remoto inmutable.

Sistema Seguro: Hospital construye un demostrador pequeño pero técnicamente defendible. La versión 1.1.0 adopta un enfoque **secure by default**: no arranca sin un secreto maestro suficientemente largo, las funciones de demo están deshabilitadas por defecto, las cookies se preparan para transporte seguro y el material criptográfico generado queda excluido del repositorio.

La metodología combina **STRIDE**, **MITRE ATT&CK**, **ITU-T X.800** y **Defense in Depth**, apoyada por RFC 6238 para TOTP, RFC 7519 para JWT, RFC 8017 para RSA-PSS, NIST SP 800-63B-4 y OWASP ASVS 5.0.0.

La pregunta de ingeniería es: **¿cómo demostrar que una nota clínica fue creada por un médico autorizado, que su contenido no fue alterado sin detección y que los eventos relevantes dejan evidencia auditable?** La respuesta se implementa mediante controles de identidad, criptografía, aplicación, persistencia y validación automatizada.

# Descripción del sistema

## Propósito y alcance funcional

Sistema Seguro: Hospital gestiona usuarios internos, pacientes, historial clínico, creación de notas firmadas, auditoría y un panel controlado para demostrar ataques de integridad. Se ejecuta localmente y no depende de servicios externos para la demostración.

Activos principales: expedientes y notas; credenciales y hashes; secretos TOTP; JWT; llaves RSA; hashes y firmas; eventos de auditoría; `SECRET_KEY`; base SQLite y archivos criptográficos.

## Roles y permisos

| Acción | Administrador | Doctor | Enfermero | Administrativo |
|---|:---:|:---:|:---:|:---:|
| Consultar expedientes | — | Sí | Sí | Sí |
| Crear y firmar nota clínica | — | Sí | — | — |
| Consultar auditoría | Sí | Sí | — | Sí |
| Verificar integridad | Sí | Sí | — | Sí |
| Gestionar usuarios | Sí | — | — | — |
| Ejecutar panel de ataque de demo | Sí | Sí | — | — |

La autorización se aplica en servidor. Una cuenta desactivada pierde autorización en la siguiente petición protegida porque el sistema vuelve a consultar su estado. La verificación histórica conserva la llave pública de médicos inactivos.

## Flujos principales

### Inicio de sesión

1. Correo y contraseña.
2. Verificación Argon2id.
3. Preautenticación breve.
4. Código TOTP de seis dígitos.
5. Descifrado del secreto TOTP sólo en memoria.
6. Emisión de JWT RS256 con emisor, audiencia, tiempos y `jti`.
7. En cada petición se verifica JWT y estado/rol vigentes.

### Creación de una nota clínica

1. Doctor autenticado accede al expediente.
2. Se valida CSRF y RBAC.
3. Se canonicaliza la nota.
4. Se calcula SHA-256.
5. La contraseña descifra temporalmente la llave privada del médico.
6. Se firma mediante RSA-PSS con SHA-256.
7. Se persisten nota, hash y firma.
8. La operación se registra en auditoría.

### Auditoría e integridad

El hash de cada evento cubre hash anterior, identificador, usuario, entidad, acción, detalle, IP y fecha/hora con separador canónico. Triggers de SQLite rechazan `UPDATE` y `DELETE` sobre `audit_log`. El verificador recalcula cadena, hashes de notas y firmas de forma independiente.

## Límites del prototipo

No cifra integralmente los campos clínicos de SQLite, no ofrece alta disponibilidad, rate limiting distribuido, HSM/KMS, SIEM ni backup inmutable. Son limitaciones explícitas.

# Arquitectura

## Vista lógica

| Área | Ubicación | Responsabilidad |
|---|---|---|
| Presentación | `app/presentacion/` | Rutas HTTP, formularios, cookies, CSRF, Jinja2 |
| Autenticación | `app/autenticacion/` | Argon2id, TOTP, preauth, JWT y contraseña |
| Dominio clínico | `app/clinico/` | Modelos y operaciones clínicas |
| Seguridad | `app/seguridad/` | Firmas, llaves, cifrado, hash chain, verificación, rate limiting, headers |
| Datos | `app/datos/` | SQLite y repositorios parametrizados |
| Ensamblado | `app/fabrica.py` | Construcción de repositorios, servicios y decoradores |

La separación es modular dentro de un mismo proceso FastAPI y no debe confundirse con aislamiento físico.

## Patrones de diseño

**Repository:** encapsula SQL.  
**Factory:** centraliza ensamblado.  
**Decorator:** agrega auditoría a operaciones clínicas.  
**Strategy:** desacopla el algoritmo de firma; RSA-PSS es la estrategia activa.

## Fronteras de confianza

1. Navegador → FastAPI: entrada no confiable.
2. Aplicación → SQLite: persistencia y transacciones.
3. Aplicación → sistema de archivos: llaves y QR.
4. Entorno → aplicación: secretos de runtime.
5. Host → red: en producción requiere TLS/reverse proxy.

# Modelo STRIDE

| Categoría | Amenaza | Controles | Riesgo residual |
|---|---|---|---|
| Spoofing | contraseña/cuenta válida robada | Argon2id, TOTP, rate limiting, JWT, revalidación | TOTP puede sufrir phishing en tiempo real |
| Tampering | modificación directa de nota/bitácora | SHA-256, RSA-PSS, hash chain con IP, triggers, verificador | control total del host puede superar controles locales |
| Repudiation | negar autoría/acción | RSA-PSS + auditoría encadenada | sin TSA externa/HSM |
| Information Disclosure | robo de TOTP, PEM, JWT o BD | AES-GCM, PEM cifrado, RBAC, cookies y no-store | BD clínica no cifrada integralmente |
| Denial of Service | fuerza bruta/bloqueo SQLite | rate limiting, transacciones breves | no distribuido/HA |
| Elevation of Privilege | uso indebido de rol/sesión | RBAC, denegaciones auditadas, revalidación de cuenta | políticas en código |

# MITRE ATT&CK

| Técnica | Aplicación al prototipo | Mitigación |
|---|---|---|
| T1078 Valid Accounts | abuso de credenciales legítimas | MFA, RBAC, revalidación y auditoría |
| T1110 Brute Force | guessing/spraying | Argon2id + rate limiting |
| T1552.004 Private Keys | robo de PEM | exclusión Git, cifrado, archivos no estáticos |
| T1565.001 Stored Data Manipulation | manipulación de expedientes | SHA-256, RSA-PSS, verificador |
| T1070 Indicator Removal | borrar evidencia | triggers + hash chain; se recomienda SIEM remoto |
| T1190 Public-Facing Application | explotar entrada web | SQL parametrizado, autoescape, CSRF, CSP |
| T1005 Data from Local System | extraer BD/llaves | separación/cifrado de secretos; residual con host comprometido |

# X.800

| Servicio X.800 | Implementación | Estado |
|---|---|---|
| Authentication | Argon2id + TOTP + JWT RS256 | Implementado |
| Access control | RBAC + revalidación | Implementado |
| Data confidentiality | cookies seguras, TOTP/PEM cifrados, HTTPS esperado | Parcial |
| Data integrity | SHA-256, RSA-PSS, hash chain | Implementado en alcance de demo |
| Non-repudiation | firma del médico + auditoría | Parcial/demostrativo |
| Audit/event detection | bitácora, login/denegación, verificador | Implementado localmente |
| Recovery | semilla/restauración/pruebas | Demo, no DR productivo |

# Defense in Depth

1. **Repositorio/SDLC:** `.gitignore`, placeholders, CI con secretos efímeros y pruebas.
2. **Host/archivos:** material criptográfico fuera de estáticos y PEM cifrados.
3. **Transporte/navegador:** HTTPS/HSTS, Secure/HttpOnly/SameSite, CSP.
4. **Identidad:** Argon2id, TOTP, rate limiting, preauth.
5. **Sesión/autorización:** JWT firmado, expiración, issuer/audience, RBAC, cuenta activa.
6. **Aplicación:** CSRF, validación, autoescape, SQL parametrizado.
7. **Datos/criptografía:** SHA-256, RSA-PSS, AES-GCM, PEM cifrados.
8. **Auditoría/detección:** hash chain, IP, triggers, verificador, exportación.
9. **Validación/recuperación:** pytest, CI, demo aislada y restauración.

# Implementación de controles

## Contraseñas y MFA

Argon2id protege hashes de contraseña. Los secretos TOTP se almacenan como `enc:v1:<blob>` usando AES-256-GCM; la clave se deriva de `SECRET_KEY` mediante HKDF-SHA256. Los códigos se verifican con RFC 6238.

## Sesión JWT

RS256 separa firma y verificación. Los tokens exigen `sub`, `iss`, `aud`, `iat`, `nbf`, `exp` y `jti`. La cuenta y el rol se revalidan contra la base en cada petición protegida.

## Firma de notas

La canonicalización fija orden de paciente, médico, diagnóstico, tratamiento y fecha. SHA-256 produce el digest y RSA-PSS firma ese digest. La llave privada del médico permanece cifrada en disco.

## Auditoría encadenada

`RepoAuditoria.insertar_encadenado()` ejecuta `BEGIN IMMEDIATE`, obtiene el hash previo, calcula el nuevo hash incluyendo `ip_origen` e inserta dentro de la misma transacción. Triggers bloquean UPDATE/DELETE.

## CSRF, cookies y cabeceras

Los POST utilizan double-submit CSRF. Cookies de sesión/preauth son HttpOnly, SameSite=Strict y Secure configurable. Middleware agrega CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, no-store y HSTS cuando corresponde.

## Configuración y repositorio

`.env.example` sólo contiene placeholders. `.gitignore` excluye `.env`, bases, PEM, llaves, QR y caches. CI genera secretos efímeros. README documenta instalación, pruebas y limitaciones.

# Pruebas y validación

La suite `tests/test_smoke.py` contiene doce pruebas que cubren: semilla/integridad inicial, RBAC, CSRF, rate limiting, concurrencia de auditoría, manipulación de hash, restauración, cifrado de secretos, manipulación de IP, revocación al desactivar usuario, headers/visor demo y firmas históricas.

Se ejecutó:

```bash
python -m compileall -q app db tests
python -m pytest -q
```

Resultado observado en el entorno de construcción:

```text
12 passed in 7.93s
```

**Limitación del entorno de construcción:** no había acceso de red para instalar el paquete oficial `pyotp`; se utilizó temporalmente, fuera del repositorio, un shim compatible para la ejecución local. El shim no forma parte del entregable. `requirements.txt` declara `pyotp` y CI instala la dependencia oficial.

Pruebas manuales recomendadas: confirmar MFA, denegaciones RBAC, creación/firma de nota, detección de alteración, rechazo de DELETE de auditoría, revocación de usuario y cabeceras HTTP.

# Resultados

| Área | Estado v1.1.0 | Evidencia |
|---|---|---|
| Secretos versionables | Mejorado | `.env.example` + `.gitignore` |
| MFA | Implementado/endurecido | TOTP + secreto cifrado |
| JWT | Endurecido | RS256, claims, issuer/audience y revalidación |
| RBAC | Implementado | rutas y pruebas |
| Firma de notas | Implementado | RSA-PSS + verificador |
| Auditoría | Implementado localmente | SHA-256, IP, concurrencia, triggers |
| CSRF | Implementado | formularios POST y logout |
| Cabeceras HTTP | Implementado | middleware + pruebas |
| CI / pruebas | Implementado | workflow sin secretos estáticos, 12 pruebas |
| Cifrado integral BD clínica | Pendiente productivo | recomendación |
| Log remoto/WORM | Pendiente productivo | recomendación |
| KMS/HSM | Pendiente productivo | recomendación |

El riesgo residual principal es el compromiso total del host; también permanecen riesgos de disponibilidad/escalabilidad por SQLite/rate limiter en memoria y confidencialidad de datos clínicos en reposo.

El repositorio final incluye código comentado, README, `.env.example`, modelo de amenazas, documentación, pruebas y evidencias. Bases SQLite, PEM, QR y `.env` reales se excluyen del control de versiones.

# Conclusiones

Sistema Seguro: Hospital v1.1.0 evoluciona de una demostración de principios criptográficos a un prototipo con un modelo de seguridad más coherente. La mejora principal consiste en cerrar brechas entre controles: MFA ya no conserva secretos en claro; JWT no mantiene acceso de cuentas deshabilitadas; la IP queda protegida por la cadena; el modo demo se separa del perfil seguro; y las pruebas cubren explícitamente controles críticos.

STRIDE mostró amenazas de identidad, integridad, evidencia, confidencialidad, disponibilidad y privilegios. MITRE ATT&CK relacionó escenarios con técnicas adversarias; X.800 distinguió servicios de seguridad; Defense in Depth confirmó distribución de controles desde repositorio/navegador hasta criptografía, persistencia y auditoría.

El prototipo cumple su propósito académico, pero para producción serían imprescindibles alta disponibilidad, TLS administrado, cifrado de almacenamiento/BD, KMS/HSM, logs remotos inmutables, backups, monitoreo continuo, gestión centralizada de identidad y evaluación normativa formal.

# Referencias

1. International Telecommunication Union. (1991). *Recommendation X.800: Security architecture for Open Systems Interconnection for CCITT applications*. ITU-T.
2. National Institute of Standards and Technology. (2025). *Digital Identity Guidelines: Authentication and Authenticator Management (NIST SP 800-63B-4)*.
3. National Institute of Standards and Technology. (2015). *Secure Hash Standard (FIPS PUB 180-4)*.
4. M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *TOTP: Time-Based One-Time Password Algorithm (RFC 6238)*.
5. Jones, M., Bradley, J., & Sakimura, N. (2015). *JSON Web Token (JWT) (RFC 7519)*.
6. Moriarty, K., Kaliski, B., Jonsson, J., & Rusch, A. (2016). *PKCS #1: RSA Cryptography Specifications Version 2.2 (RFC 8017)*.
7. MITRE. (2026). *MITRE ATT&CK Enterprise Matrix and techniques T1078, T1110, T1552.004, T1565.001, T1070, T1190 and T1005*.
8. OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*.
9. OWASP Foundation. *Cross-Site Request Forgery Prevention Cheat Sheet*.
10. OWASP Foundation. *HTTP Headers Cheat Sheet*.
