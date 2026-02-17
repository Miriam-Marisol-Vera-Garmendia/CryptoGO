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
Resuelve la protección de documentos y su compartición con usuarios que hayan sido previamente autenticados. 
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
  - Un atacante con acceso a los dispositivos.
  - Proteger la información debido a malas prácticas de seguridad de los usuarios.
  - Recuperación de llaves sin un respaldo.
  - Protección frente a adversarios con capacidades de cómputo cuántico.

## **2. Diagrama de arquitectura**

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
Declare explícitamente qué asume su sistema.

## **6. Revisión de la superficie de ataque**
Enumere todos los puntos de entrada con los que un atacante podría interactuar.
Para cada uno, describa brevemente:
* ¿Qué podría salir mal?
* ¿Qué propiedad de seguridad está en riesgo?

## **7. Restricciones de diseño derivadas de los requisitos**
Muestre cómo los requisitos se traducen en decisiones arquitectónicas.
