// Reto 2 — Emisor C2 Simulado.
// Programación Avanzada para Ciberseguridad · FCFM UANL
//
// Uso: ./emisor <IP_detector> <puerto> <intervalo_seg> <clave_xor_hex>
// Ej:  ./emisor 192.168.56.101 4444 5 5A
//
// Compilar: g++ -std=c++17 -o emisor emisor.cpp -lssl -lcrypto -lpthread
//           (requiere: sudo apt install libssl-dev)

#include <iostream>
#include <string>
#include <vector>
#include <fstream>       // escribirLogAES
#include <ctime>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <future>        // std::async, std::future
#include <mutex>         // std::mutex, std::lock_guard

// ── Variables globales para el manejador de señal ───────────────────
static volatile sig_atomic_t running = 1;
static std::vector<std::string> historial;

// Límite del historial en memoria (ventana deslizante de los últimos N mensajes)
static constexpr size_t MAX_HISTORIAL = 100;

// Mutex para serializar escrituras en std::cout desde distintos hilos
static std::mutex cout_mtx;

void manejadorSIGINT(int) {
    running = 0;
}

// ── Funciones ───────────────────────────────────────────────────────

// XOR cipher (simétrico: aplicarlo dos veces recupera el original)
std::string xorCipher(const std::string& data, char key) {
    std::string resultado = data;
    for (size_t i = 0; i < resultado.size(); ++i) {
        resultado[i] ^= key;
    }
    return resultado;
}

// Escribe el historial cifrado con AES-128-ECB en log_<timestamp>.bin.
// Se puede ejecutar desde cualquier hilo; usa cout_mtx para su salida.
void escribirLogAES(const std::vector<std::string>& mensajes,
                    const unsigned char clave[16]) {
    std::string nombre_archivo = "log_" + std::to_string(time(nullptr)) + ".bin";

    AES_KEY aesKey;
    if (AES_set_encrypt_key(clave, 128, &aesKey) != 0) {
        std::lock_guard<std::mutex> lk(cout_mtx);
        std::cerr << "Error al configurar clave AES\n";
        return;
    }

    std::ofstream archivo(nombre_archivo, std::ios::binary);
    if (!archivo) {
        std::lock_guard<std::mutex> lk(cout_mtx);
        std::cerr << "Error al abrir archivo log\n";
        return;
    }

    for (const auto& mensaje : mensajes) {
        // Padding con '\0' hasta múltiplo de AES_BLOCK_SIZE (16 bytes)
        std::string bloque = mensaje;
        while (bloque.size() % AES_BLOCK_SIZE != 0) {
            bloque += '\0';
        }

        // Cifrar bloque a bloque (AES-128-ECB)
        for (size_t i = 0; i < bloque.size(); i += AES_BLOCK_SIZE) {
            unsigned char cifrado[AES_BLOCK_SIZE];
            AES_encrypt(
                reinterpret_cast<const unsigned char*>(&bloque[i]),
                cifrado,
                &aesKey
            );
            archivo.write(reinterpret_cast<const char*>(cifrado), AES_BLOCK_SIZE);
        }
    }

    archivo.close();
    std::lock_guard<std::mutex> lk(cout_mtx);
    std::cout << "Log guardado en: " << nombre_archivo
              << " (" << mensajes.size() << " mensajes)\n";
}

// ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Uso: " << argv[0]
                  << " <IP> <puerto> <intervalo_seg> <clave_xor_hex>\n";
        return 1;
    }

    const char* ip;
    int         puerto;
    int         intervalo;
    char        clave_xor;

    try {
        ip        = argv[1];
        puerto    = std::stoi(argv[2]);
        intervalo = std::stoi(argv[3]);
        clave_xor = (char)std::stoul(argv[4], nullptr, 16);
    } catch (const std::exception&) {
        std::cerr << "Argumentos inválidos\n";
        return 1;
    }

    // Clave AES derivada de la clave XOR (primer byte, resto en cero)
    unsigned char clave_aes[16] = {};
    clave_aes[0] = clave_xor;

    // sigaction sin SA_RESTART: Ctrl+C interrumpe sleep() de inmediato
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

    // Configurar dirección del detector
    sockaddr_in destino{};
    destino.sin_family = AF_INET;
    destino.sin_port   = htons(puerto);
    if (inet_pton(AF_INET, ip, &destino.sin_addr) <= 0) {
        std::cerr << "IP inválida: " << ip << "\n";
        close(sock);
        return 1;
    }

    std::cout << "Emisor iniciado → " << ip << ":" << puerto
              << " | intervalo: " << intervalo << "s"
              << " | historial: últimos " << MAX_HISTORIAL << " msgs"
              << " | Ctrl+C para cerrar\n\n";

    int contador = 0;

    // future del envío UDP en vuelo; se espera antes de cada nueva iteración
    // para no saturar hilos y garantizar orden de salida en consola.
    std::future<void> futuro_envio;

    while (running) {
        ++contador;

        // Construir payload en texto claro
        std::string payload = "ALIVE:"
                            + std::to_string(contador) + ":"
                            + std::to_string(time(nullptr));

        // ── Ventana deslizante: conservar sólo los últimos MAX_HISTORIAL ──
        historial.push_back(payload);
        if (historial.size() > MAX_HISTORIAL) {
            historial.erase(historial.begin()); // descarta el más antiguo
        }

        // Cifrar con XOR
        std::string cifrado = xorCipher(payload, clave_xor);

        // Esperar a que el envío anterior haya terminado antes de lanzar uno nuevo.
        // Esto evita condiciones de carrera sobre sock/destino y mezcla en cout.
        if (futuro_envio.valid()) {
            futuro_envio.wait();
        }

        // ── Envío asíncrono ──────────────────────────────────────────────
        // Se captura por VALOR (cifrado, payload, contador) para que el hilo
        // tenga su propia copia aunque la iteración avance.
        // sock y destino se capturan por referencia: son válidos durante todo
        // el bucle y no se modifican concurrentemente (el wait() de arriba lo
        // garantiza).
        futuro_envio = std::async(
            std::launch::async,
            [cifrado, payload, contador, &sock, &destino]() {
                ssize_t r = sendto(
                    sock,
                    cifrado.data(),
                    cifrado.size(),
                    0,
                    reinterpret_cast<sockaddr*>(&destino),
                    sizeof(destino)
                );
                std::lock_guard<std::mutex> lk(cout_mtx);
                if (r < 0) perror("sendto");
                else std::cout << "Heartbeat #" << contador
                               << " enviado: \"" << payload << "\"\n";
            }
        );

        // Esperar el intervalo (EINTR si llega Ctrl+C)
        sleep(static_cast<unsigned>(intervalo));
    }

    // Asegurar que el último envío en vuelo haya terminado
    if (futuro_envio.valid()) {
        futuro_envio.wait();
    }

    // ── Cierre simultáneo: escritura del log + cierre del socket ────────
    //
    //   hilo principal        hilo async (futuro_log)
    //   ───────────────       ─────────────────────────
    //   close(sock)      ║    escribirLogAES(...)  ← I/O a disco
    //   (retorno rápido) ║    cifra y escribe bin
    //   futuro_log.get() ←── (join implícito al terminar)
    //
    std::cout << "\nCerrando — escribiendo log AES y cerrando socket simultáneamente...\n";

    auto futuro_log = std::async(
        std::launch::async,
        [&clave_aes]() {
            escribirLogAES(historial, clave_aes);
        }
    );

    close(sock);        // hilo principal: libera fd mientras el log se escribe

    futuro_log.get();   // esperar a que el hilo de log termine antes de salir

    return 0;
}
