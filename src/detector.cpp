// Reto 2 — Detector Defensivo
// Programación Avanzada para Ciberseguridad · FCFM UANL
//
// Uso: ./detector <puerto> <clave_xor_hex>
// Ej:  ./detector 4444 5A
//
// Requisitos:
//   1. Escuchar paquetes UDP en el puerto indicado
//   2. Descifrar el payload con la misma clave XOR del emisor
//   3. Calcular intervalo promedio y desviación estándar entre mensajes
//   4. Emitir alerta si desviación < 0.5s (patrón de beaconing regular)
//   5. Al cerrar (Ctrl+C): generar reporte.json con IOCs
//
// Compilar: make detector

#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <fstream>
#include <sstream>
#include <csignal>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ── Variables globales para el manejador de señal ───────────────────
static bool running = true;

struct Registro {
    std::string payload_descifrado;
    std::string ip_origen;
    double      timestamp;  // segundos desde epoch (con decimales)
};

static std::vector<Registro> registros;

void manejadorSIGINT(int) {
    running = false;
}

// ── Implementa las siguientes funciones ─────────────────────────────

// XOR cipher (idéntica a la del emisor)
std::string xorCipher(const std::string& data, char key) {
    // TODO: misma implementación que en emisor.cpp
    return "";
}

// Calcula media y desviación estándar de un vector de intervalos en segundos
void calcularEstadisticas(const std::vector<double>& intervalos,
                          double& media, double& desviacion) {
    // TODO: media = suma / n
    // TODO: desviacion = sqrt(suma_de_(xi - media)^2 / n)
    media     = 0.0;
    desviacion = 0.0;
}

// Genera reporte.json con los IOCs detectados
// Estructura requerida (ver especificación en el documento del Reto):
//   ip_emisor, puerto_destino, total_mensajes,
//   intervalo_promedio_seg, desviacion_estandar,
//   patron, iocs[], alerta, nivel
void generarReporte(const std::string& ip_emisor, int puerto,
                    double media, double desviacion) {
    // TODO: construir el JSON manualmente con std::ostringstream
    // TODO: escribir en "reporte.json"
    // Ejemplo de campo:
    //   oss << "  \"ip_emisor\": \"" << ip_emisor << "\",\n";
}

// ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Uso: " << argv[0] << " <puerto> <clave_xor_hex>\n";
        return 1;
    }

    int  puerto    = std::stoi(argv[1]);
    char clave_xor = (char)std::stoul(argv[2], nullptr, 16);

    signal(SIGINT, manejadorSIGINT);

    // TODO: crear socket UDP
    // int sock = socket(AF_INET, SOCK_DGRAM, 0);

    // TODO: configurar sockaddr_in local con el puerto y hacer bind()

    std::cout << "Detector escuchando en puerto " << puerto
              << " | Ctrl+C para generar reporte\n\n";

    char    buffer[1024];
    sockaddr_in origen{};
    socklen_t   origen_len = sizeof(origen);

    while (running) {
        // TODO: recvfrom() con timeout (SO_RCVTIMEO de 1 segundo
        //       para que el bucle pueda revisar 'running')

        // TODO: registrar timestamp con steady_clock::now()

        // TODO: descifrar payload con xorCipher(buffer, clave_xor)

        // TODO: almacenar en registros{}

        // TODO: calcular intervalos acumulados y verificar desviación
        //       si desviacion < 0.5: imprimir alerta de beaconing
    }

    // Al salir: calcular estadísticas finales y generar reporte
    std::vector<double> intervalos;
    for (size_t i = 1; i < registros.size(); ++i)
        intervalos.push_back(registros[i].timestamp - registros[i-1].timestamp);

    double media = 0.0, desviacion = 0.0;
    if (!intervalos.empty())
        calcularEstadisticas(intervalos, media, desviacion);

    std::string ip_emisor = registros.empty() ? "desconocida"
                                               : registros[0].ip_origen;

    generarReporte(ip_emisor, puerto, media, desviacion);
    std::cout << "reporte.json generado.\n";

    return 0;
}
