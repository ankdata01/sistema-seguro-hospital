# Matriz de cumplimiento de la entrega

Esta matriz relaciona los requisitos académicos de la actualización con los artefactos de Sistema Seguro: Hospital v1.1.0.

## Estructura del documento

| Requisito | Ubicación | Estado |
|---|---|---|
| Portada | Informe académico final entregado externamente en PDF | Cumplido |
| Resumen | Informe final | Cumplido |
| Introducción | Informe final | Cumplido |
| Descripción del sistema | Informe final | Cumplido |
| Arquitectura | Informe final + `docs/arquitectura.md` | Cumplido |
| Modelo STRIDE | Informe final + `docs/modelo-amenazas.md` | Cumplido |
| MITRE ATT&CK | Informe final + `docs/modelo-amenazas.md` | Cumplido |
| X.800 | Informe final + `docs/modelo-amenazas.md` | Cumplido |
| Defense in Depth | Informe final + `docs/modelo-amenazas.md` | Cumplido |
| Implementación de controles | Informe final + `docs/seguridad.md` + código | Cumplido |
| Pruebas y validación | Informe final + `TESTING.md` + `tests/` | Cumplido |
| Resultados | Informe final + `evidencias/` | Cumplido |
| Conclusiones | Informe final | Cumplido |
| Referencias | Informe final | Cumplido |

## Repositorio GitHub

| Requisito | Evidencia | Estado |
|---|---|---|
| Anexos/código o carpeta de código | `app/`, `db/`, `tests/`, `docs/anexos-codigo.md` | Cumplido |
| Código comentado | Docstrings y comentarios en módulos críticos | Cumplido |
| README con instrucciones para ejecutar | `README.md` | Cumplido |
| Configuración sin contraseñas ni claves reales | `.env.example`, `.gitignore`, secretos efímeros de CI | Cumplido |
| Evidencias de pruebas | `evidencias/resultado-validacion.txt`, CI y `tests/test_smoke.py` | Cumplido |

## Controles adicionales incorporados en v1.1.0

Se endurecieron secretos, TOTP, llaves JWT, claims, revalidación de sesiones, cadena de auditoría, cookies/CSRF, cabeceras HTTP, rutas de demo, manejo de contraseñas, auditoría de denegaciones y verificación histórica de firmas. El detalle está en `docs/revision-seguridad.md`.

El informe académico final se entrega externamente en PDF. El repositorio conserva el código, la documentación técnica complementaria y las evidencias reproducibles de validación. `docs/informe-tecnico-extendido.md` funciona como referencia técnica ampliada.
