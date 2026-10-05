# Reto 2 — Monitor Defensivo de Comportamiento C2 Simulado

**Materia:** Programación Avanzada para Ciberseguridad (AD2026) · LSTI · FCFM UANL
**Profesora:** Dra. Perla Marlene Viera González
**Entrega:** tag `reto2-entrega` en este repositorio

## Integrantes

| Nombre | Matrícula | Módulo |
|---|---|---|
| Carlos Adrián Ramos Zacarías | 2013681 | Emisor |
| Marcos Adrián González Soto | 2037908 | Emisor |
| Axel Simón Moreno Lozano | 2010484 | Emisor |
| Anateyssi Hernández Meza | 2024072 | Detector |
| Miguel Eduardo Flores Salazar | 1993905 | Detector |

La división del trabajo y lo que aprendió cada integrante están en [`docs/analisis.md`](docs/analisis.md).

## Descripción

Sistema de dos programas en C++17 que corren en VMs distintas dentro de la misma red interna (*Internal Network*). Un emisor simula el comportamiento de un cliente C2 (heartbeat periódico cifrado) y un detector lo analiza de forma defensiva y genera un reporte de IOCs.

| Programa | Archivo | VM | Función |
|---|---|---|---|
| Emisor C2 simulado | `src/emisor.cpp` | VM-1 | Envía por UDP un heartbeat cifrado con XOR cada N segundos. Al cerrar con Ctrl+C escribe un log cifrado con AES-128 con los últimos 100 mensajes |
| Detector defensivo | `src/detector.cpp` | VM-2 | Recibe y descifra los heartbeats, calcula el intervalo promedio y la desviación estándar, alerta si el patrón es demasiado regular y genera `reporte.json` con los IOCs |

```
 VM-1 (emisor)                         VM-2 (detector)
 ┌──────────────┐   UDP, payload XOR   ┌──────────────┐
 │ ALIVE:n:ts   │ ───────────────────► │ descifra     │
 │ log AES .bin │                      │ intervalos   │
 └──────────────┘                      │ reporte.json │
                                       └──────────────┘
```

Payload del heartbeat (antes de cifrar): `ALIVE:<contador>:<timestamp_unix>`

## Requisitos

- Linux (probado en: [DISTRO Y VERSIÓN])
- `g++` con soporte C++17 y `make`
- OpenSSL y sus cabeceras de desarrollo
- Dos VMs en la misma red interna [NOMBRE DE LA RED EN VIRTUALBOX]
- Wireshark (opcional, para capturar el tráfico)

```bash
sudo apt install build-essential libssl-dev
```

## Compilación

Desde la raíz del repositorio, en cada VM:

```bash
make
```

Genera `bin/emisor` y `bin/detector` con `-std=c++17 -Wall -Wextra -O2` (enlaza con `-lssl -lcrypto -lpthread`).
Para limpiar: `make clean`.

Las especificaciones completas están en el documento **RETO2_PAC_AD2026.pdf** publicado en Teams.

## Uso

Ambos programas deben usar la **misma clave XOR** (un byte en hexadecimal, `00`-`FF`).

### 1. Detector (VM-2)

```bash
./bin/detector <puerto> <clave_xor_hex>

# Ejemplo
./bin/detector 4444 5A
```

### 2. Emisor (VM-1)

```bash
./bin/emisor <IP_detector> <puerto> <intervalo_seg> <clave_xor_hex>

# Ejemplo
./bin/emisor 192.168.56.101 4444 5 5A
```

### 3. Cierre

- `Ctrl+C` en el emisor: escribe `log_<timestamp>.bin` en el directorio actual.
- `Ctrl+C` en el detector: escribe `reporte.json` en el directorio actual.

Copiar ambos archivos a `evidence/` para la entrega.

## Ejemplo de salida

Detector:

```
Detector escuchando en puerto 4444 | Ctrl+C para generar reporte

[1] 192.168.56.100:56944 -> "ALIVE:1:1791174158"
[2] 192.168.56.100:56944 -> "ALIVE:2:1791174163" | intervalo=5.001s media=5.001s desv=0.000s
[3] 192.168.56.100:56944 -> "ALIVE:3:1791174168" | intervalo=5.002s media=5.001s desv=0.000s
  [ALERTA] Posible beaconing desde 192.168.56.100 (desviación 0.000s < 0.5s)
```

`reporte.json`:

```json
{
  "ip_emisor": "192.168.56.100",
  "puerto_destino": 4444,
  "total_mensajes": 42,
  "intervalo_promedio_seg": 5.0003,
  "desviacion_estandar": 0.0012,
  "patron": "beaconing_regular",
  "iocs": [
    {"tipo": "ip", "valor": "192.168.56.100"},
    {"tipo": "puerto_udp", "valor": 4444},
    {"tipo": "payload_patron", "valor": "ALIVE:"}
  ],
  "alerta": true,
  "nivel": "ALTO"
}
```

## Verificación de resultados

**Reporte del detector:** revisar `evidence/reporte.json`. La alerta se activa cuando la desviación estándar de los intervalos es menor a 0.5 s (patrón demasiado regular).

**Log AES del emisor:** `log_<timestamp>.bin` está cifrado con AES-128 en modo ECB (sin IV). La llave AES se deriva de la clave XOR: el primer byte es la clave XOR y los 15 restantes son `00`. Cada mensaje `ALIVE:<contador>:<timestamp>` se rellena con bytes `00` hasta un múltiplo de 16 bytes y se guardan como máximo los últimos 100. Comando de verificación (ejemplo con clave `5A`):

```bash
openssl enc -d -aes-128-ecb -nopad -K 5A000000000000000000000000000000 \
  -in evidence/log_<timestamp>.bin | tr -s '\0' '\n'
```

Debe imprimir un mensaje `ALIVE:<contador>:<timestamp>` por línea.

**Tráfico:** abrir `evidence/captura_wireshark.pcapng` y filtrar con `udp.port == 4444`. El payload se ve cifrado con XOR (no legible).

## Estructura del repositorio

```
reto2-equipo/
├── src/
│   ├── emisor.cpp
│   └── detector.cpp
├── bin/                         # generados por make
├── evidence/
│   ├── captura_wireshark.pcapng
│   ├── reporte.json
│   ├── log_<timestamp>.bin
│   ├── screenshots/             # mínimo 3 capturas
│   └── IA/                      # capturas de las conversaciones con IA
├── docs/
│   └── analisis.md              # explicación del sistema y preguntas de reflexión
├── Makefile
├── README.md
├── ETHICS.md
└── AI_USAGE.md
```

## Decisiones de diseño y limitaciones

- **Concurrencia:** el envío de cada heartbeat y la escritura del log usan `std::async`.
- **Estadística:** la desviación estándar es poblacional (divide entre n). El detector usa `std::chrono::steady_clock` para medir intervalos con precisión de milisegundos.
- **Cifrado XOR:** es solo ofuscación, no protege el contenido. Se usa porque el reto simula un C2 básico.
- **Log AES:** usa ECB por simplicidad. Es inseguro (bloques iguales producen texto cifrado igual) y la llave derivada de un solo byte es débil; en producción se usaría CBC o CTR con IV aleatorio y una llave generada con una KDF.
- **Detector:** cuenta cualquier paquete UDP que llegue al puerto y necesita al menos 3 mensajes para emitir una alerta.

## Aviso ético

Todo el trabajo se realizó en VMs con red *Internal Network*. El emisor **nunca** debe ejecutarse hacia internet ni hacia la red del campus. Ver [`ETHICS.md`](ETHICS.md).

## Uso de IA

El uso de herramientas de IA está declarado en [`AI_USAGE.md`](AI_USAGE.md). Las capturas de las conversaciones que lo respaldan están en [`evidence/IA/`](evidence/IA/):

| Captura | Tema |
|---|---|
| `chat_01_configuracion_vm.png` | Configuración de las VMs |
| `chat_02_makefile_1.png`, `chat_03_makefile_2.png` | Makefile |
| `chat_04_revision_de_codigo.png` | Revisión de código |
| `chat_05_error_1.png`, `chat_06_error_2.png` | Depuración de errores |
| `chat_07_json_y_log.png` | `reporte.json` y log AES |
| `chat_08_wireshark.png` | Captura de tráfico con Wireshark |
