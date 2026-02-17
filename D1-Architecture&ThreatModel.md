# **Architecture & Threat Model**
## **Objetivo**
Diseñar el Secure Digital Document Vault a nivel de sistema antes de implementar la criptografía.
Este entregable asegura que su equipo:
- Comprenda qué propiedades de seguridad debe proporcionar el sistema
- Identifique atacantes realistas
- Defina supuestos de confianza
- Traduza los requisitos de seguridad en decisiones arquitectónicas
- Ninguna criptografía sólida puede compensar una arquitectura débil.

## **1. Descripción general del sistema**
* ¿Qué problema resuelve su bóveda?
* ¿Cuáles son las funcionalidades principales?
* ¿Qué está explícitamente fuera del alcance del sistema?

## **2. Diagrama de arquitectura (Obligatorio)**

## **3. Requisitos de seguridad**
Enumere explícitamente las propiedades de seguridad que su sistema debe proporcionar.

## **4. Modelo de amenazas**
**Activos - ¿Que se protege?**
- Documentos cifrados.
- Llaves simétricas
- Llaves privadas.
- Credenciales de autenticación
- Integridad de los datos.
- Contraseñas utilizadas para proteger llaves.
- Firmas digitales asociadas a cada documento
- Sistema de respaldo y recuperación de llaves.
  
  **Activos secuendario**
  - Código fuente del sistema.
  - Metadatos de los documentos (nombre, fecha, propietario)
  - Historial de acceso o compartición
  - Repositorio GitHub del proyecto.

**Amenazas - ¿Contra quienes nos defendemos?**
- Atacantes que puedan interceptar, leer o modificar la información.
- Atacantes externos.
- Usuarios no autorizados o autenticados
- Robo de llaves privadas almacenadas sin protección adecuada.
- Ataques de fuerza bruta contra contraseñas que protegen las llaves.
- Exposición de llaves simétricas
- Alteración de llaves públicas.
- Suplantación de identidad mediante llaves falsas
- Pérdida de llaves sin mecanismo de recuperación.
- Falta de validación de integridad en respaldo de llaves

## **5. Supuestos de confianza**
- El usuario protege su contraseña, es decir, que no la comparte y no es trivial
- El sistema operativo brinda aleatoriedad segura (CSPRNG) para las claves y nonces (no usa RNG débil)
- Las llaves públicas de los destinatarios son auténticas puesto que se obtienen por un canal confiable desde un inicio
- El almacenamiento ya sea local o remoto es no confiable puesto que puede leer, modificar o borrar contenedores
- Sus dependencias criptográficas no están modificadas de manera maliciosa

## **6. Revisión de la superficie de ataque**
Enumere todos los puntos de entrada con los que un atacante podría interactuar.
Para cada uno, describa brevemente:
* ¿Qué podría salir mal?
* ¿Qué propiedad de seguridad está en riesgo?

## **7. Restricciones de diseño derivadas de los requisitos**
| **Requisito** | **Restricción de diseño** |
| ------------- | ------------------------- |
| Confindecialidad del archivo | Usar AEAD para cifrar contenido con una clave unica por cada archivo |
| Integridad | AEAD con validación estricta, un rechazo sin falla |
| Autenticidad del remitente | Implementaciond e firmas digitales sobre los contenedores |
| Verificación previa | Antes del decifrado verificar que cumpla el siguiente flujo: verificar firma -> desenvolver clave -> AEAD descrypt |
| Compartición con multiples destinitarios | Cuenta con cifrado híbrido, envolviendo la clave de sesión para cada receptor con su clave pública |
| Resitencia de ataques por nonce | Un NONCE único por cifrado, prohibiendo la reutilización |





