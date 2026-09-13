# Evidencias de validación

Esta carpeta contiene evidencia textual reproducible de la revisión de Sistema Seguro: Hospital v1.1.0. No debe contener bases de datos, claves privadas, QR TOTP, tokens, capturas con credenciales ni archivos `.env` reales.

## Reproducción

1. Configure variables según `README.md`.
2. Instale `requirements.txt` y `requirements-dev.txt`.
3. Ejecute `python -m db.semilla`.
4. Ejecute `python -m pytest -q`.
5. Ejecute `python -m compileall -q app db tests`.
6. Revise que Git no proponga material sensible.

`resultado-validacion.txt` registra el resultado observado durante la revisión. El CI es la ejecución recomendada con dependencias oficiales.
