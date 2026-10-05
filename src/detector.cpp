// Reto 2 — Detector Defensivo
// Programación Avanzada para Ciberseguridad · FCFM UANL
//
// Uso: ./detector <puerto> <clave_xor_hex>
// Ej:  ./detector 4444 5A
//
// Compilar: make detector

#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ── Variables globales para el manejador de señal ───────────────────
static volatile sig_atomic_t running = 1;

struct Registro {
    std::string payload_descifrado;
    std::string ip_origen;
    double      timestamp;  // segundos (steady_clock, con decimales)
};

static std::vector<Registro> registros;

void manejadorSIGINT(int) {
    running = 0;
}

// ── Funciones ───────────────────────────────────────────────────────

// XOR cipher (idéntica a la del emisor)
std::string xorCipher(const std::string& data, char key) {
    std::string resultado = data;
    for (size_t i = 0; i < resultado.size(); ++i) {
        resultado[i] ^= key;
    }
    return resultado;
}

// Calcula media y desviación estándar (poblacional) de los intervalos
void calcularEstadisticas(const std::vector<double>& intervalos,
                          double& media, double& desviacion) {
    if (intervalos.empty()) {
        media = 0.0;
        desviacion = 0.0;
        return;
    }

    double suma = 0.0;
    for (double intervalo : intervalos) suma += intervalo;
    media = suma / intervalos.size();

    double suma_cuadrados = 0.0;
    for (double intervalo : intervalos)
        suma_cuadrados += (intervalo - media) * (intervalo - media);
    desviacion = std::sqrt(suma_cuadrados / intervalos.size());
}

// Genera reporte.json con los IOCs detectados
void generarReporte(const std::string& ip_emisor, int puerto,
                    double media, double desviacion) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4);

    // Se necesitan al menos 2 intervalos (3 mensajes) para hablar de patrón
    bool alerta = (registros.size() >= 3 && desviacion < 0.5);
    std::string patron = alerta ? "beaconing_regular" : "irregular";
    std::string nivel  = alerta ? "ALTO" : "BAJO";

    oss << "{\n"
        << "  \"ip_emisor\": \"" << ip_emisor << "\",\n"
        << "  \"puerto_destino\": " << puerto << ",\n"
        << "  \"total_mensajes\": " << registros.size() << ",\n"
        << "  \"intervalo_promedio_seg\": " << media << ",\n"
        << "  \"desviacion_estandar\": " << desviacion << ",\n"
        << "  \"patron\": \"" << patron << "\",\n"
        << "  \"iocs\": [\n"
        << "    {\"tipo\": \"ip\", \"valor\": \"" << ip_emisor << "\"},\n"
        << "    {\"tipo\": \"puerto_udp\", \"valor\": " << puerto << "},\n"
        << "    {\"tipo\": \"payload_patron\", \"valor\": \"ALIVE:\"}\n"
        << "  ],\n"
        << "  \"alerta\": " << (alerta ? "true" : "false") << ",\n"
        << "  \"nivel\": \"" << nivel << "\"\n"
        << "}\n";

    std::ofstream archivo("reporte.json");
    if (archivo.is_open()) {
        archivo << oss.str();
    } else {
        std::cerr << "Error al crear el archivo reporte.json\n";
    }
}

// Segundos actuales según steady_clock (monótono, ideal para intervalos)
static double ahoraSegundos() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

// ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Uso: " << argv[0] << " <puerto> <clave_xor_hex>\n";
        return 1;
    }

    int  puerto;
    char clave_xor;
    try {
        puerto    = std::stoi(argv[1]);
        clave_xor = (char)std::stoul(argv[2], nullptr, 16);
    } catch (const std::exception&) {
        std::cerr << "Argumentos inválidos\n";
        return 1;
    }

    // sigaction sin SA_RESTART: Ctrl+C interrumpe recvfrom() de inmediato
    struct sigaction sa{};
    sa.sa_handler = manejadorSIGINT;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);

    // Crear socket UDP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    // Timeout de 1 s para que el bucle pueda revisar 'running'
    timeval tv{};
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(sock);
        return 1;
    }

    // Configurar dirección local y hacer bind()
    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port        = htons(puerto);

    if (bind(sock, (sockaddr*)&local, sizeof(local)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    std::cout << "Detector escuchando en puerto " << puerto
              << " | Ctrl+C para generar reporte\n\n";

    char        buffer[1024];
    sockaddr_in origen{};
    socklen_t   origen_len;

    while (running) {
        origen_len = sizeof(origen);
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                             (sockaddr*)&origen, &origen_len);

        if (n < 0) {
            // Timeout o interrupción por señal: volver a revisar 'running'
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            perror("recvfrom");
            break;
        }

        // Registrar timestamp en cuanto llega el paquete
        double ts = ahoraSegundos();

        // Descifrar payload usando la longitud real (puede contener '\0')
        std::string cifrado(buffer, n);
        std::string payload = xorCipher(cifrado, clave_xor);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &origen.sin_addr, ip_str, sizeof(ip_str));

        registros.push_back({payload, ip_str, ts});

        std::cout << "[" << registros.size() << "] " << ip_str << ":"
                  << ntohs(origen.sin_port) << " -> \"" << payload << "\"";

        // Calcular intervalos acumulados
        if (registros.size() >= 2) {
            std::vector<double> intervalos;
            for (size_t i = 1; i < registros.size(); ++i)
                intervalos.push_back(registros[i].timestamp -
                                     registros[i - 1].timestamp);

            double media, desviacion;
            calcularEstadisticas(intervalos, media, desviacion);

            std::cout << std::fixed << std::setprecision(3)
                      << " | intervalo=" << intervalos.back() << "s"
                      << " media=" << media << "s"
                      << " desv=" << desviacion << "s";

            // Con al menos 2 intervalos ya se puede evaluar regularidad
            if (intervalos.size() >= 2 && desviacion < 0.5) {
                std::cout << "\n  [ALERTA] Posible beaconing desde " << ip_str
                          << " (desviación " << desviacion << "s < 0.5s)";
            }
        }
        std::cout << "\n";
    }

    close(sock);
    std::cout << "\nCerrando detector...\n";

    // Estadísticas finales y reporte
    std::vector<double> intervalos;
    for (size_t i = 1; i < registros.size(); ++i)
        intervalos.push_back(registros[i].timestamp - registros[i - 1].timestamp);

    double media = 0.0, desviacion = 0.0;
    calcularEstadisticas(intervalos, media, desviacion);

    std::string ip_emisor = registros.empty() ? "desconocida"
                                              : registros[0].ip_origen;

    generarReporte(ip_emisor, puerto, media, desviacion);
    std::cout << "reporte.json generado.\n";

    return 0;
}
