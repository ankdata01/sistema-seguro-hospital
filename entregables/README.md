# Entregables

La fuente versionada del informe es `../docs/informe-final.md` y el generador reproducible es `../generar_informe_latex.py`.

El archivo editable `Clinica_Segura_Informe_Final_v1.1.0.docx` forma parte del paquete de entrega distribuible, pero no es necesario para construir ni ejecutar el repositorio. Se conserva como artefacto de entrega separado para evitar depender de un binario Office dentro del historial Git.

Para generar LaTeX:

```bash
python generar_informe_latex.py
```

Para compilar PDF con `pdflatex` disponible:

```bash
python generar_informe_latex.py --pdf
```
