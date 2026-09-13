# Modelo de amenazas — Clínica Segura v1.1.0

> STRIDE, MITRE ATT&CK, X.800 y Defense in Depth se aplican como marcos complementarios. ATT&CK describe comportamientos adversarios; X.800 se usa como taxonomía de servicios/mecanismos, no como certificación.

## 1. Activos y fronteras de confianza

**Activos críticos:** credenciales, secretos TOTP, JWT, llaves RSA privadas, llaves públicas asociadas a firmas, expedientes clínicos, hashes/firma de notas, bitácora, `SECRET_KEY` y base SQLite.

**Fronteras:** navegador↔FastAPI; presentación↔servicios; servicios↔repositorios; aplicación↔SQLite; aplicación↔material criptográfico; host local↔red.

## 2. STRIDE

| Categoría | Escenario relevante | Impacto | Controles v1.1.0 | Residual |
|---|---|---|---|---|
| Spoofing | Uso de contraseña robada o cuenta válida | Acceso no autorizado | Argon2id, TOTP, rate limiting, JWT RS256, revalidación de cuenta activa | TOTP no es resistente a phishing en tiempo real |
| Tampering | UPDATE directo de nota o bitácora | Diagnóstico alterado/evidencia falsificada | SHA-256, RSA-PSS, cadena hash con IP, triggers anti-UPDATE/DELETE, verificador | SQLite no es WORM; control total del host supera el modelo |
| Repudiation | Médico niega autoría | Disputa sin evidencia | Firma RSA-PSS por médico, auditoría encadenada y eventos de sesión | Sin TSA externa ni HSM |
| Information Disclosure | Robo de TOTP, PEM, JWT o expediente | Pérdida de confidencialidad | TOTP AES-GCM, PEM cifrado, RBAC, cookies HttpOnly/SameSite, no-store | Base clínica sin cifrado aplicativo integral |
| Denial of Service | Intentos masivos o bloqueo de SQLite | Indisponibilidad | Rate limiting y transacciones cortas | Rate limiter en memoria y SQLite limitan escalabilidad |
| Elevation of Privilege | Rol intenta función ajena o usuario desactivado conserva JWT | Acceso indebido | RBAC por ruta, auditoría de denegaciones, revalidación por petición | Políticas centralizadas serían necesarias en producción |

## 3. MITRE ATT&CK

| Técnica | Riesgo | Cobertura/mitigación |
|---|---|---|
| T1078 Valid Accounts | abuso de credenciales legítimas | MFA, revalidación de activo, RBAC, auditoría |
| T1110 Brute Force | guessing/spraying | Argon2id + rate limiting por IP/email/MFA |
| T1552.004 Unsecured Credentials: Private Keys | robo de PEM | `.gitignore`, directorio no estático, PEM cifrados, 0600 cuando aplica |
| T1565.001 Stored Data Manipulation | modificación de expedientes | SHA-256, RSA-PSS, verificación on-demand |
| T1070 Indicator Removal | borrado/modificación de evidencia | triggers, hash chain; producción requiere log remoto/SIEM |
| T1190 Exploit Public-Facing Application | explotación de entrada web | SQL parametrizado, autoescape, CSRF, CSP, docs API desactivadas |
| T1005 Data from Local System | extracción de BD/llaves | separación y cifrado de secretos; residual alto con host comprometido |

## 4. X.800

| Servicio | Implementación | Estado |
|---|---|---|
| Authentication | Argon2id + TOTP; JWT RS256 | Implementado |
| Access control | RBAC y revalidación de cuenta | Implementado |
| Data confidentiality | cookies seguras, TOTP/PEM cifrados, HTTPS requerido | Parcial: falta cifrado integral de BD |
| Data integrity | SHA-256, RSA-PSS, hash chain | Implementado en demo |
| Non-repudiation | firma por médico + auditoría | Parcial/demostrativo |
| Security audit | bitácora, login/denegación, verificador | Implementado localmente |
| Security recovery | semilla/restauración y pruebas | Demo; no sustituye DR |

## 5. Defense in Depth

1. **Repositorio/SDLC:** `.gitignore`, placeholders, CI con secretos efímeros y pruebas.
2. **Host/archivos:** material criptográfico fuera de estáticos, PEM cifrados, permisos restrictivos.
3. **Transporte/navegador:** HTTPS/HSTS, Secure/HttpOnly/SameSite, CSP y cabeceras.
4. **Identidad:** Argon2id, TOTP, rate limiting, preautenticación de 5 minutos.
5. **Sesión/autorización:** JWT firmado, expiración, issuer/audience, RBAC y cuenta activa.
6. **Aplicación:** CSRF, validación, autoescape, SQL parametrizado.
7. **Datos/criptografía:** SHA-256, RSA-PSS, AES-GCM TOTP, PEM cifrados.
8. **Auditoría/detección:** hash chain, IP incluida, triggers, verificador, exportación.
9. **Validación/recuperación:** pytest, CI, pruebas destructivas aisladas y restauración.

Para producción faltan principalmente TLS gestionado, WAF/reverse proxy, KMS/HSM, cifrado de volumen/DB, SIEM/log remoto, backups inmutables, HA, EDR, segregación de red y monitoreo.
