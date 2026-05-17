# CryptoGO
Implementación de una bóveda digital segura para el cifrado, compartición y verificación de documentos, aplicando principios de criptografía.

## Miembros del equipo
- Casillas Herrera Leonardo Didier - Tester/QA
- Flores Melquiades Evelyn Jasmin - Líder del proyecto
- Vera Garmendia Miriam Marisol - Desarrolladora
- Gaytan Herrera Belen - Diseñadora UX/UI

## Instalación
### En Windows
```bash
pip install -e .[dev]
```
### En Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

## Ejecutar pruebas
```bash
pytest
```

## Ejecutar interfaz
```bash
python -m cryptogo.gui
# o
python cryptogo/gui.py 
```
## Documentación completa

La documentación completa del diseño, modelo de amenazas, decisiones de seguridad del proyecto (D1-D6) se encuentra en:

```text
README_Information.md
```

