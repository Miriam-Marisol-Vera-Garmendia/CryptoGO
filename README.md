# CryptoGO

Implementación de una bóveda digital segura para el cifrado, compartición y verificación de documentos, aplicando principios de criptografía.

## Miembros del equipo
- Casillas Herrera Leonardo Didier - Tester/QA
- Flores Melquiades Evelyn Jasmin - Líder del proyecto
- Vera Garmendia Miriam Marisol - Desarrolladora
- Gaytan Herrera Belen - Diseñadora UX/UI

## Requisitos del Sistema
- Python >= 3.10
- pip (administrador de paquetes de Python)

## Instalación

### Windows
Abre la terminal en la carpeta raíz del proyecto y ejecuta:
```bash
pip install -e .[dev]
```

### Linux / MacOS
Abre la terminal en la carpeta raíz del proyecto y ejecuta:
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

## Resumen de la Arquitectura

El sistema funciona bajo un esquema de cifrado híbrido y firmas digitales obligatorias (Verify-then-Decrypt):
1. **Cifrado Simétrico (ChaCha20-Poly1305):** Cada documento se cifra con una clave simétrica única generada al vuelo. Los metadatos y la lista de destinatarios se protegen como Datos Asociados Autenticados (AAD).
2. **Cifrado Híbrido (ECIES-secp256k1):** La clave simétrica del documento se cifra de forma independiente para cada destinatario autorizado con su clave pública.
3. **Firma Digital (Ed25519):** El remitente firma el contenedor completo (metadatos, destinatarios, nonce y ciphertext).
4. **Verificación Previa:** Al abrir el archivo, el destinatario verifica la firma del remitente antes de descifrar cualquier contenido.

El diagrama de arquitectura completo está disponible en:
https://github.com/user-attachments/assets/11ce5535-26b7-4ffd-9cf7-b176045b03bd

## Ejemplos de Uso

### 1. Generar Llaves
* Iniciar la interfaz gráfica.
* Seleccionar "Generar par de llaves de acceso" para obtener la clave pública y privada.
* Seleccionar "Generar llaves de firma" para obtener el par de firma digital.

### 2. Cifrar y Compartir un Archivo
* Seleccionar el archivo original en la sección de cifrado.
* Agregar los nombres y claves públicas de cifrado de los destinatarios autorizados.
* Ingresar la clave privada del emisor.
* Presionar "Cifrar y Compartir" para generar el contenedor digital.

### 3. Descifrar y Verificar un Archivo
* Seleccionar la carpeta del contenedor digital en la sección de descifrado.
* Proporcionar la clave privada del destinatario.
* Ingresar la clave pública de firma del remitente.
* Presionar "Descifrar y Verificar" para restaurar el archivo original.

## Supuestos de Seguridad

* **Canal Seguro:** Se asume que el intercambio de claves públicas se realiza mediante un canal externo de confianza para evitar suplantaciones de identidad.
* **Dispositivo Confiable:** Se asume que el dispositivo local del usuario está libre de malware que pueda capturar las llaves en memoria.

## Limitaciones Conocidas

* **Entornos Comprometidos:** El sistema no protege contra un sistema operativo atacado a nivel de privilegios elevados (root o administrador).
* **Cómputo Cuántico:** Los algoritmos de clave pública utilizados (secp256k1 y Ed25519) no son resistentes a ataques cuánticos futuros.
* **Contraseñas Débiles:** La protección de las llaves privadas en el keystore depende directamente de la fortaleza de la contraseña del usuario, aunque se utilicen algoritmos costosos como Scrypt.

## Documentación completa

La documentación completa del diseño, modelo de amenazas, decisiones de seguridad del proyecto (D1-D6) se encuentra en:

```text
README_Information.md
```