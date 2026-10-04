// Reto 2 — Emisor C2 Simulado
// Programación Avanzada para Ciberseguridad · FCFM UANL
//
// Uso: ./emisor <IP_detector> <puerto> <intervalo_seg> <clave_xor_hex>
// Ej:  ./emisor 192.168.56.101 4444 5 5A
//
// Requisitos:
//   1. Enviar heartbeat cifrado con XOR cada <intervalo> segundos
//   2. Payload: "ALIVE:<contador>:<timestamp_unix>" → cifrar con XOR
//   3. Al cerrar (Ctrl+C): escribir log cifrado AES-128 en log_<timestamp>.bin
//
// Compilar: make emisor  (requiere: sudo apt install libssl-dev)

#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>

// ── Variables globales para el manejador de señal ───────────────────
static bool running = true;
static std::vector<std::string> historial;  // guarda los mensajes enviados

void manejadorSIGINT(int) {
    running = false;
}

// ── Implementa las siguientes funciones ─────────────────────────────

// XOR cipher: aplica llave byte a byte sobre toda la cadena
// Propiedad: xorCipher(xorCipher(data, key), key) == data
std::string xorCipher(const std::string& data, char key) {
    // TODO: iterar sobre data, aplicar ^ key a cada byte, devolver resultado
    return "";
}

// Escribe el log cifrado con AES-128 al cerrar el emisor
// Nombre del archivo: "log_" + timestamp_unix + ".bin"
void escribirLogAES(const std::vector<std::string>& mensajes,
                    const unsigned char clave[16]) {
    // TODO 1: generar nombre dinámico con time(NULL)
    // TODO 2: AES_KEY aesKey; AES_set_encrypt_key(clave, 128, &aesKey);
    // TODO 3: ajustar cada mensaje a múltiplo de AES_BLOCK_SIZE (16 bytes)
    // TODO 4: AES_encrypt para cada bloque
    // TODO 5: escribir en std::ofstream(nombre, std::ios::binary)
}

// ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Uso: " << argv[0]
                  << " <IP> <puerto> <intervalo_seg> <clave_xor_hex>\n";
        return 1;
    }

    const char* ip        = argv[1];
    int         puerto    = std::stoi(argv[2]);
    int         intervalo = std::stoi(argv[3]);
    char        clave_xor = (char)std::stoul(argv[4], nullptr, 16);

    // Clave AES (derivada de la clave XOR para simplificar el ejemplo)
    unsigned char clave_aes[16] = {};
    clave_aes[0] = clave_xor;

    // Registrar manejador de Ctrl+C
    signal(SIGINT, manejadorSIGINT);

    // TODO: crear socket UDP
    // int sock = socket(AF_INET, SOCK_DGRAM, 0);

    // TODO: configurar sockaddr_in con ip y puerto destino

    std::cout << "Emisor iniciado → " << ip << ":" << puerto
              << " | intervalo: " << intervalo << "s | Ctrl+C para cerrar\n";

    int contador = 0;
    while (running) {
        // TODO: construir payload "ALIVE:<contador>:<timestamp>"
        // TODO: cifrar con xorCipher(payload, clave_xor)
        // TODO: sendto() con el payload cifrado
        // TODO: agregar payload (sin cifrar) al historial
        // TODO: imprimir en consola "Heartbeat #N enviado"
        // TODO: sleep(intervalo)
        ++contador;
    }

    // Al salir: escribir log cifrado con AES
    std::cout << "\nCerrando — escribiendo log AES...\n";
    escribirLogAES(historial, clave_aes);

    return 0;
}
