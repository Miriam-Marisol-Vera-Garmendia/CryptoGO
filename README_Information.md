# **D1 - Architecture & Threat Model**
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

# **D2 - Secure Symmetric Encryption Module**
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

# **D3 - Hybrid Encryption**
## **Objetivo**
Extender el sistema para soportar el intercambio seguro de archivos entre múltiples usuarios utilizando cifrado híbrido.
Después de esta entrega, el sistema debe permitir:
- Un archivo cifrado una sola vez
- Múltiples destinatarios autorizados
- Solo esos destinatarios pueden descifrar

## **Objetivo de Seguridad**
Después de D3:
Solo los destinatarios previstos pueden acceder al archivo, incluso si el contenedor cifrado se expone públicamente.
Usarás cifrado híbrido porque NO se cifran archivos directamente con claves públicas.
En su lugar (como se vio en clase):
* Generar una clave simétrica aleatoria (clave del archivo).
* Cifrar el archivo usando AEAD (de D2).
* Cifrar la clave del archivo usando la clave pública de cada destinatario.
* Almacenar todas las claves cifradas en el contenedor.

Estructura conceptual
Archivo → AEAD → texto cifrado
Clave del archivo → cifrada con la clave pública de Alice
         → cifrada con la clave pública de Bob
         → cifrada con la clave pública de Carol

## **1. Cifrado para múltiples destinatarios**
El sistema soporta múltiples destinatarios autorizados (Alice, Bob y Carol), por lo que cumple con el requisito de operar con al menos dos usuarios. Para proteger un archivo se genera una clave simétrica aleatoria (**file key**) que se usa para cifrar el contenido completo del archivo una sola vez mediante ChaCha20-Poly1305.
Cunado el archivo este cifrado, la **file key** no se transmite en texto plano; sino que, se cifra de forma independiente para cada destinatario usando su clave mediante **ECIES**. El contenedor final almacena una entrada por destinatario con su identificador y su clave cifrada; de este modo, el archivo se cifra una sola vez y puede ser descifrado por cualquier usuario autorizado.

## **2. Descifrado basado en el destinatario**
Cuando un usuario abre un archivo compartido, el sistema revisa la sección de destinatario dentro del contenedor para identificar la entrada correspondiente; una vez localizada, toma la llave cifrada asociada a ese usuario y la intenta descifrar con su clave privada. Si la clave privada corresponde a la clave pública utilizada al cifrar esa entrada, el usuario recupera la **file key**; porteriormente, esta se emplea para descifrar el contenido del archivo con ChaCha20-Poly1305 y si el usuario no está autorizado, si la clave privada es incorrecta, o si el contenedor fue modificado, el descifrado falla de forma segura.

## **3. Mecanismo de identificación de claves**
Para que cada destinatario localice su clave de forma correcta, se define un mecanismo de identificación basado en dos elementos: un identificador explícito de usuario (**id**) que nos indicará a qué usuario pertenece cada entrada y una huella digital de la clave pública (**key_id**) la cual estará asociada a dicha entrada con una clave pública.
Este mecanismo reduce el riesgo de confusión porque, dado un identificador, siempre se localiza la misma entrada correspondiente. Además, la inclusión de la huella digital de la clave pública dificulta que un intercambio de identidades o una sustitución de claves pase desapercibido.

## **4. Formato actualizado del cotenedor**
El contenedor seguro incorpora toda la información necesaria para el cifrado compartido, su estructura incluye los metadatos generales del archivo, la lista de destinatarios con sus claves cifradas, el **ciphertext** del archivo y el **tag** de autenticación. Conceptualmente queda así:
```json
{
  "metadata": { ... },
  "recipients": [
    { "id": "alice", "key_id": "...", "encrypted_key": "..." },
    { "id": "bob", "key_id": "...", "encrypted_key": "..." }
  ],
  "nonce": "...",
  "ciphertext": "...",
  "tag": "..."
}
```

## **5. Integración de Metadata + AAD**
El sistema incorpora información crítica que debe quedar autenticada aunque no esté cifrada directamente al AAD, en nuestro caso el AAD incluye los metadatos, la lista de destinatarios , los identificadores de clave y los identificadores de algoritmos utilizados.
Esto es importante debido a que protege contra modificaciones no autorizadas del contenedor por parte de quien no posea las claves; por lo que, cualquier intento de agregaro eliminar un destinatario o de intercambiar identidades será detectado por el sistema.

## **6. Uso seguro de claves públicas**
En nuestro diseño se hace un uso adecuado de las claves públicas, ya que estas no se emplean para cifrar archivos completos debido a que eso sería ineficiente y no correspondería al modelo de cifrado híbrido, Debido a eso, se usan para cifrar un dato de tamaño reducido que es la **file key** (llave simétrica con la que se protege un archivo).
Para ello se eligió un esquema de estilo **ECIES** que nos permite cifrar de forma segura la clave simétrica para cada destinatario.

## **7. Explicación del diseño híbrido**
- ¿Por qué se usa cifrado híbrido?
Porque combina la eficiencia para proteger archivos completos que nos la brinda el cifrado simétrico junto con la permisiva de distribuir la clave de forma segura entre varios destinatarios sin transmitirla en texto plano que brinda el cifrado asimétrico.

- ¿Por qué sigue siendo necesario el cifrado simétrico?
Sigue siendo necesario porque Chacha20-Poly 1305 es el más adecuado para cifrar grandes volúmenes de datos y proporciona confidencialidad e integridad en una sola operación.

- ¿Por qué se requiere cifrado de clave por destinatario?
El cifrado de clave por destinatario es necesario porque cada usuario tiene su propia clave pública, así cada usuario autorizado puede recuperar la clave del archivo usando su clave privada, mientras que uno no autorizado no podrá hacerlo.

## **8. Decisiones de seguridad**
* ¿Cómo identifican los destinatarios su clave
Los destinatarios identifican su clave buscando su entrada dentro de la lista **recipients**, usando el **id** del usuario y validando el **key_id** asociado a su clave pública, con esto se reducen posibles errores o confusiones al seleccionar una clave cifrada.

* ¿Qué pasa si un atacante modifica la lista de destinatarios?
En caso de que un atacante modifique la lista de destinatarios, el sistema detecta la alteración debido a que esa información forma parte del AAD; debido a ello, al intentar abrir el archivo, la verificación de autenticidad falla y el descifrado no se completa, lo que protege contra la adición, eliminación o sustitución no autorizada de destinatarios.

* ¿Qué pasa si la clave pública es incorrecta?
Si la clave pública usada para cifrar es incorrecta, el destinatario real no podrá recuperar la **file key** con su clave privada; ya que, el cifrado de la clave falla y el archivo no puede abrirse, por lo que el sistema falla de manerasegura sin exponer el contenido.

# **D5 - Firmas Digitales y Autenticación**

## **1. Diseño de Firma**

### **1.1 Algoritmo elegido**

- **Algoritmo utilizado**:  
  

- **Razón de elección**:  
  

### **1.2 ¿Qué datos se firman?**

- **Datos incluidos en la firma**:  
  

- **Importancia de firmar estos datos**:  
  

### **1.3 ¿Por qué se requiere hashing antes de firmar?**

- **Función del hash**:  
  

- **Relación con la integridad**:  
  

## **2. Decisiones de Seguridad**

### **2.1 ¿Por qué firmar el texto cifrado y no el texto plano?**

- **El texto cifrado es lo que realmente se almacena y transmite**: El sistema firma los datos que viajan y se almacenan dentro del contenedor, no el contenido original que solo existe temporalmente antes del cifrado.

- **El receptor verifica la firma ANTES de descifrar**: La firma se verifica antes de cualquier operación de descifrado, en ese momento el receptor todavía no tiene acceso al texto plano.

- **Firmar el texto cifrado garantiza integridad del contenido cifrado**: La verificación de la firma fallará y el archivo será rechazado si un atacante modifica el texto cifrado después de que fue firmado.

- **Consistencia con el modelo de seguridad**: La firma protege el contenedor final con los metadatos, destinatarios y el contenido cifrado para asegurar que no hayan sido alterados desde que fueron firmados.

### **2.2 ¿Qué pasa si la firma no se verifica primero?**

- **Sin autenticidad del origen**: No habría forma de confirmar quién creó realmente el archivo, cualquier persona podría generar o modificar un contenedor y tratar de hacerlo pasar como legítimo.

- **Ataque de suplantación**: Un atacante podría tomar un contenedor existente, alterarlo y reclamar que fue creado por otro usuario.

- **Error confuso**: El sistema podría intentar descifrar primero y fallar después con un error de autenticación del cifrado en lugar de rechazar directamente el archivo por tener una firma inválida.

- **La verificación es obligatoria**: La firma debe verificarse **antes** de cualquier descifrado. Si la firma es inválida, no está presente o se verifica con una clave pública incorrecta, el contenedor se rechaza y el descifrado **nunca** se ejecuta.

### **2.3 ¿Qué pasa si se excluyen los metadatos?**

- **Manipulación del nombre de archivo**: Un atacante podría cambiar el nombre original del archivo para hacerlo parecer otro tipo de documento o para ocultar su verdadero contenido.

- **Manipulación de destinatarios**: Un atacante podría alterar la información de los usuarios autorizados provocando confusión sobre quién puede acceder al archivo.

- **Suplantación del firmante**: Un atacante podría cambiar la información relacionada con el autor del archivo para hacer creer que el contenedor fue creado por otra persona.

- **La firma debe cubrir todo el contexto del contenedor**: No basta con firmar solo el texto cifrado, también deben protegerse los metadatos, la lista de destinatarios, el nonce, el texto cifrado y la etiqueta de autenticación.

- **Ataques de contexto bloqueados**: Un atacante podría modificar información importante sin tocar directamente el texto cifrado si los metadatos no se incluyen en la firma; cualquier cambio no autorizado provoca que la verificación falle y el contenedor sea rechazado antes de descifrarlo.
