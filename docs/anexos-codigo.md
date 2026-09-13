# Anexos de código y entrega

## A. Repositorio/carpeta de código

El código ejecutable se encuentra en `app/`, `db/` y `tests/`. Los módulos incluyen docstrings y comentarios donde la intención de seguridad o la lógica no es obvia.

## B. Ejecución

`README.md` contiene instalación, variables de entorno, creación de la semilla, inicio de Uvicorn, roles, pruebas y limitaciones.

## C. Configuración sin secretos

`.env.example` contiene sólo placeholders. Los valores reales de `SECRET_KEY` y `DEMO_PASSWORD` se inyectan por entorno. `.gitignore` impide versionar bases de datos, archivos `.env`, llaves, PEM y QR.

## D. Evidencias

La carpeta `evidencias/` contiene el resultado de validación y las instrucciones para reproducir pruebas. La suite está en `tests/test_smoke.py` y el CI en `.github/workflows/tests.yml`.

## E. Documentación

- `docs/informe-final.md`: documento académico completo.
- `docs/modelo-amenazas.md`: STRIDE, ATT&CK, X.800 y Defense in Depth.
- `docs/arquitectura.md`: arquitectura y fronteras.
- `docs/seguridad.md`: catálogo de controles.
- `docs/revision-seguridad.md`: cambios de endurecimiento v1.1.0.
- `docs/demo.md`: demostración segura.
