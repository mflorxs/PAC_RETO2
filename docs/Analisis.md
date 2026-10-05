# Análisis y reflexión — Reto 2

## Descripción del sistema

* **Emisor (Cliente C2 / Agente):** Módulo en C++ encargado de establecer la comunicación saliente desde el host hacia el servidor de control. Envía paquetes periódicos de estado (*heartbeats*) a través de UDP encriptados mediante cifrado XOR y mantiene un registro cifrado con AES-128 en el almacenamiento local.
* **Detector (Analizador / IDS):** Módulo que recibe los paquetes UDP, realiza el descifrado XOR, calcula los intervalos de interarribo entre mensajes y determina la desviación estándar de los tiempos. Si la desviación estándar cae por debajo del umbral establecido (ej. 0.5 s), clasifica el comportamiento como *beaconing* regular y genera una alerta en `reporte.json`.

---

## Decisiones de diseño

* **Estructura modular:** Se separaron las responsabilidades entre la captura/parseo de red, la capa criptográfica y el motor de análisis estadístico para facilitar la depuración de código y el mantenimiento individual de componentes.
* **Análisis de regularidad:** Se utilizó el cálculo de la desviación estándar de los intervalos de tiempo en el detector para automatizar la identificación del canal encubierto sin depender únicamente de firmas de contenido.
* **Complejidad de implementación:** Los mayores retos técnicos consistieron en la sincronización precisa de tiempos para medir los intervalos de recepción sin falso ruido de red, la correcta implementación de AES-128 sobre los datos persistidos y la depuración de buffers en C++.

---

CAPITULO 4: PREGUNTAS FINALES DE REFLEXION

1. ¿Qué haría diferente el emisor para que el detector no lo identificara como beaconing regular?

El emisor introduciría jitter: en lugar de esperar exactamente N segundos entre heartbeats, esperaría N ± un porcentaje aleatorio (por ejemplo 20-30 %), usando std::uniform_real_distribution. Esto aumenta la desviación estándar de los intervalos por encima del umbral de 0.5 s del detector. Además, podría variar el tamaño del payload con relleno aleatorio y cambiar el puerto de destino de forma periódica. Aun así, un detector más sofisticado (por ejemplo, uno que analice la distribución de los intervalos en ventanas largas) podría identificarlo, por lo que el jitter dificulta la detección pero no la elimina.

2. ¿Por qué cifrar el log con AES y no solo con XOR?

XOR con una llave corta y repetida es trivial de romper: si se conoce o se adivina parte del texto plano (como el prefijo ALIVE:), se recupera la llave directamente, y además no ofrece difusión, ya que cada byte cifrado depende de un solo byte de la llave. AES-128 es un cifrado de bloque estándar, diseñado para resistir el criptoanálisis conocido, con confusión y difusión robustas. Como el log permanece almacenado en disco y podría ser recuperado por un tercero, necesita una protección real y no solo ofuscación.

En nuestra implementación usamos AES-128 en modo ECB por simplicidad, con la llave derivada de la clave XOR. ECB no usa IV y cifra bloques iguales de forma idéntica, lo que filtra patrones; en producción usaríamos CBC o CTR con IV aleatorio y una llave generada con una KDF, no derivada de un solo byte.

3. ¿Qué regla de Suricata escribirías para detectar este tráfico automáticamente en producción?

Regla por frecuencia (patrón de beaconing):

alert udp $HOME_NET any -> any 4444 (msg:"Posible beaconing C2 UDP regular"; flow:to_server; threshold:type both, track by_src, count 5, seconds 30; classtype:trojan-activity; sid:1000001; rev:1;)

Regla por contenido (si se conoce la llave XOR; con la llave 0x5A, "ALIVE:" cifrado es 1B 16 13 0C 1F 60):

alert udp $HOME_NET any -> any 4444 (msg:"Heartbeat C2 simulado (payload XOR)"; content:"|1B 16 13 0C 1F 60|"; depth:6; classtype:trojan-activity; sid:1000002; rev:1;)

Limitación: Suricata no calcula la desviación estándar de los intervalos, por lo que threshold solo aproxima la regularidad del tráfico. La regla por contenido depende de conocer la llave.

4. Si el equipo es de 2+ personas: ¿cómo dividieron el trabajo entre el módulo emisor y el detector? Documenta qué aprendió cada integrante.

Miguel Eduardo Flores Salazar
- Aportación: estructura del repositorio en GitHub, Makefile, ETHICS.md con los nombres del equipo, creación de analisis.md y subida de capturas a evidence/.
- Aprendió: organización de un repositorio con GitHub Classroom, compilación reproducible con Makefile y gestión de colaboradores.

Marcos Adrián González Soto
- Aportación: punto 1.2 del reto (detector), revisión de la rúbrica, actualización del repositorio con sus avances y organización de las capturas de uso de IA.
- Aprendió: recepción UDP, descifrado XOR, cálculo de intervalos y desviación estándar, generación de reporte.json.

Anateyssi Hernández Meza
- Aportación: modificaciones a emisor.cpp y detector.cpp, documentadas en Word (Modificación EMISOR y Programa DETECTOR).
- Aprendió: funcionamiento interno de ambos programas y depuración de código C++.

Carlos Adrián Ramos Zacarías
- Aportación: punto 1 del reto (documento reto2_P1_PAC.docx) y verificación del acceso al repositorio.
- Aprendió: configuración del entorno de VMs y trabajo colaborativo con GitHub.

Axel Simón Moreno Lozano
- Aportación: redacción del README y respuesta de algunas de las preguntas de reflexión de este documento.
- Aprendió: documentación reproducible de un proyecto, evasión de detección con jitter, diferencias entre AES y XOR y reglas de Suricata.

Todos participaron en las pruebas y en la revisión del repositorio.
