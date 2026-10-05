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

## Preguntas de reflexión

### 1. ¿Qué haría diferente el emisor para que el detector no lo identificara como beaconing regular?

El emisor introduciría *jitter*: en lugar de esperar exactamente $N$ segundos entre *heartbeats*, esperaría $N \pm$ un porcentaje aleatorio (por ejemplo 20-30 %), usando `std::uniform_real_distribution`[cite: 2]. Esto aumenta la desviación estándar de los intervalos por encima del umbral de 0.5 s del detector[cite: 2]. Además, podría variar el tamaño del *payload* con relleno aleatorio y cambiar el puerto de destino de forma periódica[cite: 2]. Aun así, un detector más sofisticado (por ejemplo, uno que analice la distribución de los intervalos en ventanas largas) podría identificarlo, por lo que el *jitter* dificulta la detección pero no la elimina[cite: 2].

### 2. ¿Por qué cifrar el log con AES y no solo con XOR?

XOR con una llave corta y repetida es trivial de romper: si se conoce o se adivina parte del texto plano (como el prefijo `ALIVE:`), se recupera la llave directamente, y además no ofrece difusión, ya que cada byte cifrado depende de un solo byte de la llave[cite: 2]. AES-128 es un cifrado de bloque estándar, diseñado para resistir el criptoanálisis conocido, con confusión y difusión robustas[cite: 2]. Como el log permanece almacenado en disco y podría ser recuperado por un tercero, necesita una protección real y no solo ofuscación[cite: 2].

En nuestra implementación usamos AES-128 en modo ECB por simplicidad, con la llave derivada de la clave XOR[cite: 2]. ECB no usa IV y cifra bloques iguales de forma idéntica, lo que filtra patrones; en producción usaríamos CBC o CTR con IV aleatorio y una llave generada con una KDF, no derivada de un solo byte[cite: 2].

### 3. ¿Qué regla de Suricata escribirías para detectar este tráfico automáticamente en producción?

**Regla por frecuencia (patrón de beaconing):**[cite: 2]

```suricata
alert udp $HOME_NET any -> any 4444 (msg:"Posible beaconing C2 UDP regular"; flow:to_server; threshold:type both, track by_src, count 5, seconds 30; classtype:trojan-activity; sid:1000001; rev:1;)
```[cite: 2]

**Regla por contenido (si se conoce la llave XOR; con la llave `0x5A`, `ALIVE:` cifrado es `1B 16 13 0C 1F 60`):**[cite: 2]

```suricata
alert udp $HOME_NET any -> any 4444 (msg:"Heartbeat C2 simulado (payload XOR)"; content:"|1B 16 13 0C 1F 60|"; depth:6; classtype:trojan-activity; sid:1000002; rev:1;)