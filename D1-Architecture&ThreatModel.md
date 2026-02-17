# **Architecture & Threat Model**
## **Objetivo**
Diseñar la Bóbeda de Seguridad Digital de Documentos a nivel de sistema antes de implementar la criptografía.
Este entregable asegura que su equipo:
- Comprenda qué propiedades de seguridad debe proporcionar el sistema
- Identifique atacantes realistas
- Defina supuestos de confianza
- Traduza los requisitos de seguridad en decisiones arquitectónicas
- Ninguna criptografía sólida puede compensar una arquitectura débil.

## **1. Descripción general del sistema**
* ¿Qué problema resuelve la bóveda?  
Resuelve el problema de proteger documentos digitales frente a accesos no autorizados, manipulación de contenido y suplantación de identidad durante el almacenamiento y la compartición.  
La bóveda garantiza que si un atacante obtiene acceso al contenedor cifrado o al medio de almacenamiento, no pueda conocer el contenido del archivo ni modificarlo, también permite verificar la autenticidad del remitente antes de confiar en el documento recibido.

* ¿Cuáles son las funcionalidades principales?
  - El sistema debe permitir compartir archivos de forma segura con varios usuarios.
  - Se requiere un mecanismo de respaldo para las llaves criptográficas.
  - La autenticidad de los documentos debe garantizarse mediante firmas digitales obligatorias.
  - Las llaves deben gestionarse usando funciones KDF.
  - Es necesario implementar un proceso de recuperación de llaves.
  - Antes de descifrar cualquier archivo, la firma digital debe validarse.
  - Cada archivo debe protegerse usando cifrado autenticado (AEAD).
  - Se debe generar una llave simétrica independiente para cada archivo.
  - Las llaves simétricas deben protegerse mediante cifrado híbrido utilizando las llaves públicas de los destinatarios.

* ¿Qué NO está dentro del alcance de la boveda?  
  - Defender contra un SO comprometido.
  - Protección contra un atacante con acceso físico a los dispositivos.
  - No se incluye un sistema de detección de intrusiones.
  - Proteger la información debido a malas prácticas de seguridad de los usuarios.
  - Recuperación de llaves sin un respaldo.
  - Protección frente a adversarios con capacidades de cómputo cuántico.

## **2. Diagrama de arquitectura**
![Diagrama de Arquitectura](https://github.com/user-attachments/assets/60cb5be4-17b1-44ac-acbd-e62ad2f949b0)

## **3. Requisitos de seguridad**
* Confidencialidad del contenido:  
Un atacante que obtenga un documento cifrado no debe poder conocer el contenido del archivo sin la llave privada correcta del destinatario o sin la llave simétrica protegida. 

* Integridad del contenido:  
Si el documento cifrado o sus metadatos asociados fueron modificados, el sistema debe detectarlo y rechazar el descifrado por AEAD inválido y/o por firma digital inválida. 

* Autenticidad del remitente:  
El receptor debe poder verificar que el archivo tiene la firma digitaldel remitente esperado antes de descifrar cualquier contenido. 

* Confidencialidad de llaves privadas:  
Las llaves privadas no deben almacenarse en texto plano. Deben cifrarse localmente usando una clave derivada con KDF a partir de una contraseña. 
 
* Protección contra manipulación:  
Un atacante no debe poder forzar al sistema a “descifrar primero y verificar después”. La verificación de LA firma digital es un requisito previo al descifrado. También se protege la integridad del contenido y los metadatos mediante cifrado AEAD y cualquier alteración debe provocar que el descifrado no se realice.

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
- El usuario protege su contraseña, es decir, que no la comparte y no es trivial.
- El sistema operativo brinda aleatoriedad segura (CSPRNG) para las claves y nonces (no usa RNG débil).
- Las llaves públicas de los destinatarios son auténticas puesto que se obtienen por un canal confiable desde un inicio.
- El almacenamiento ya sea local o remoto es no confiable puesto que puede leer, modificar o borrar contenedores.
- Sus dependencias criptográficas no están modificadas de manera maliciosa.

## **6. Revisión de la superficie de ataque**
### Entrada de archivos
* ¿Qué podría salir mal?
  - Carga de archivos excesivamente grandes (denegación de servicio).
  - Uso de rutas maliciosas.
  - Ingreso de datos corruptos o formatos inesperados.

* ¿Qué propiedad de seguridad está en riesgo?
  - Disponibilidad.
  - Integridad del sistema.
---
### Análisis de metadatos
* ¿Qué podría salir mal?
  - Manipulación de la lista de destinatarios.
  - Alteración del algoritmo o versión del contenedor.

* ¿Qué propiedad de seguridad está en riesgo?
  - Integridad.
  - Autenticidad.
---
### Importación / exportación de llaves
* ¿Qué podría salir mal?
  - Sustitución de llaves públicas por llaves maliciosas.
  - Exfiltración de llaves privadas.

* ¿Qué propiedad de seguridad está en riesgo?
  - Confidencialidad.
  - Autenticidad.
---
### Ingreso de contraseñas
* ¿Qué podría salir mal?
  - Uso de contraseñas débiles.

* ¿Qué propiedad de seguridad está en riesgo?
  - Confidencialidad.
---
### Flujo de compartición
* ¿Qué podría salir mal?
  - Ataques Man-in-the-Middle que alteren el contenedor cifrado.
  - Sustitución de la llave pública del destinatario.
  - Modificación de los destinatarios autorizados.

* ¿Qué propiedad de seguridad está en riesgo?
  - Confidencialidad.
  - Autenticidad.
---
### Verificación de firmas
* ¿Qué podría salir mal?
  - Aceptar firmas inválidas.
  - Verificar después del descifrado.

* ¿Qué propiedad de seguridad está en riesgo?
  - Integridad.
  - Autenticidad.
---
### Argumentos de la línea de comandos (CLI)
* ¿Qué podría salir mal?
  - Contraseñas como texto en la línea de comandos.
  - Sobrescritura accidental de archivos.

* ¿Qué propiedad de seguridad está en riesgo?
  - Confidencialidad.
  - Integridad operativa.

## **7. Restricciones de diseño derivadas de los requisitos**
| **Requisito** | **Restricción de diseño** |
| ------------- | ------------------------- |
| Confindecialidad del archivo | Usar AEAD para cifrar contenido con una clave unica por cada archivo |
| Integridad | AEAD con validación estricta, un rechazo sin falla |
| Autenticidad del remitente | Implementaciond e firmas digitales sobre los contenedores |
| Verificación previa | Antes del decifrado verificar que cumpla el siguiente flujo: verificar firma -> desenvolver clave -> AEAD descrypt |
| Compartición con multiples destinitarios | Cuenta con cifrado híbrido, envolviendo la clave de sesión para cada receptor con su clave pública |
| Resitencia de ataques por nonce | Un NONCE único por cifrado, prohibiendo la reutilización |





