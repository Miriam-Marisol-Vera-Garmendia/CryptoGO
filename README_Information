# **D1-Architecture & Threat Model**
## **Objetivo**
Diseñar la Bóveda de Seguridad Digital de Documentos a nivel de sistema antes de implementar la criptografía.
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

# **D2-Secure Symmetric Encryption Module**
## **Objetivo**
Implementar un módulo de cifrado seguro de archivos que garantice:
- Confidencialidad
- Integridad
- Detección de manipulación
Utilizando cifrado autenticado moderno.
Este módulo se convierte en el núcleo criptográfico del Secure Digital Document Vault (Bóveda Segura de Documentos Digitales).
En esta etapa, tu sistema cifra archivos únicamente para un solo propietario (aún no hay funcionalidad para compartir archivos)

## **1. Cifrado seguro de archivos**
El sistema cifra archivos utilizando ChaCha20-Poly1305, un algoritmo moderno de cifrado autenticado que combina cifrado simétrico con verificación de integridad.

El proceso de cifrado sigue los siguientes pasos:

1. Se genera una clave secreta segura de 256 bits.
2. Se genera un nonce único de 12 bytes para cada operación de cifrado.
3. Se definen metadatos autenticados (AAD) que no serán cifrados pero sí protegidos contra manipulación.
4. El archivo original es cifrado utilizando ChaCha20.
5. Se genera automáticamente una etiqueta de autenticación (Poly1305) que permite verificar la integridad del contenido durante el descifrado.

El resultado del proceso incluye:
* Nonce
* Metadatos autenticados
* Ciphertext
* Tag de autenticación

Esto garantiza que el archivo almacenado en la bóveda esté protegido contra lectura o modificación no autorizada.

## **2. AEAD obligatorio**
Se usa ChaCha20-Poly1305 debido a que proporciona:
- Confidencialidad del contenido
- Integridad del ciphertext
-Autenticación de metadatos mediante AAD

## **3. Gestión de nonce/IV**
El algoritmo ChaCha20-Poly1305 requiere un nonce de 96 bits (12 bytes).

Para cada operación de cifrado:
1. Se genera un nonce único usando os.urandom(12).
2. El nonce no necesita mantenerse secreto, pero nunca debe repetirse con la misma clave.

El nonce se almacena junto con el archivo cifrado dentro del contenedor de la bóveda para que pueda utilizarse durante el proceso de descifrado.

## **4. Protección de metadatos**
El sistema protege ciertos metadatos utilizando AAD (Additional Authenticated Data).

Ejemplos de metadatos protegidos:

* Nombre del archivo
* Fecha de creación
* Identificador del documento
* Tamaño original del archivo

Estos metadatos no se cifran, pero sí se incluyen en el proceso de autenticación.
Si un atacante intenta modificarlos, el proceso de descifrado fallará.

Esto evita ataques donde se manipula información contextual del archivo almacenado.

## **5. Detección de manipulación**

ChaCha20-Poly1305 genera automáticamente una etiqueta de autenticación (authentication tag) mediante el algoritmo Poly1305.

Durante el proceso de descifrado:

1. El sistema verifica la autenticidad del ciphertext y de los metadatos.
2. Si los datos han sido modificados, el algoritmo produce un error.
3. El archivo no se descifra.

Esto permite detectar:

* Modificación del ciphertext
* Alteración de metadatos
* Corrupción del archivo
* Intentos de ataque por manipulación del contenedor

## **6. Aleatoriedad segura**
Para garantizar la generación segura de valores aleatorios en el sistema se utilizan las fuentes de aleatoriedad proporcionadas como lo son:
- ChaCha20Poly1305.generate_key(): Esta función nos generara una clave criptográfica segura utilizando un generador de números aleatorios criptográficamente seguro.  
- os.urandom(12): Esta función se utiliza para generar un nonce de 12 bytes.
El nonce generado se utiliza en el algoritmo ChaCha20-Poly1305, donde deberá ser único para cada operación de cifrado con la misma clave.

## **7. Decisiones de seguridad**
* ¿Por qué usar AEAD en lugar de “cifrado + hash”?
Se debe a que AEAD resuelve correctamente confidencialidad e integridad autenticada en una sola construcción, evitando errores comunes como:
  - Verificación después de descrifrar.
  - Hashear el plaintext en lugar del ciphertext.
  - Utilización de un MAC sin vincular metadatos.

* ¿Qué ocurre si el nonce se repite?
Al utilizar ChaCha20-Poly1035 el reutilizar un nonce con la misma clave compromete la seguridad, debido a ello el nonce deberá ser único por cifrado.

* ¿Contra qué atacante se defiende el sistema?
  - Alguien que puede leer el almacenamiento.
  - Alguien que intente forzar descifrando con datos alterados.
  - Alguien que puede mnodificar el contenedor.
