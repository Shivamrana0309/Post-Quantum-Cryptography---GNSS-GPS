#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iomanip>

#include "../common/types.hpp"
#include "../common/config.hpp"
#include "../common/crypto.hpp"

int main() {
    uint16_t listen_port = pqc_gnss::config::DEFAULT_BROADCAST_PORT;

    std::cout << "====================================================\n";
    std::cout << "        PQC GNSS GROUND RECEIVER SIMULATOR          \n";
    std::cout << "====================================================\n";
    std::cout << "[*] Listening Port       : " << listen_port << "\n";
    std::cout << "[*] PQC Scheme Expected  : " << pqc_gnss::config::PQC_SIGNATURE_SCHEME << "\n";
    std::cout << "[*] Anti-Replay Guard    : Active (Window + Timestamp Freshness)\n";
    std::cout << "----------------------------------------------------\n";

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[!] Error creating socket.\n";
        return 1;
    }

    // Set socket reuse option
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);

    if (bind(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::cerr << "[!] Error binding socket to port " << listen_port << "\n";
        close(sock);
        return 1;
    }

    std::cout << "[+] Receiver online. Awaiting GNSS broadcast packets...\n\n";

    pqc_gnss::AntiReplayGuard replay_guard;
    std::vector<uint8_t> rx_buffer(65535);

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        ssize_t bytes_received = recvfrom(sock, rx_buffer.data(), rx_buffer.size(), 0,
                                          reinterpret_cast<sockaddr*>(&client_addr), &client_len);

        if (bytes_received < 0) {
            std::cerr << "[!] Error receiving packet.\n";
            continue;
        }

        const size_t expected_min_size = sizeof(pqc_gnss::NavigationMessage) +
                                         pqc_gnss::config::MOCK_PQC_PUBKEY_SIZE +
                                         pqc_gnss::config::MOCK_PQC_SIGNATURE_SIZE;

        if (static_cast<size_t>(bytes_received) < expected_min_size) {
            std::cout << "[!] REJECTED: Malformed packet of size " << bytes_received << " bytes.\n";
            continue;
        }

        // 1. Unpack Navigation Message Payload
        pqc_gnss::NavigationMessage nav_msg{};
        pqc_gnss::deserialize_nav_message(rx_buffer.data(), sizeof(pqc_gnss::NavigationMessage), nav_msg);

        // 2. Unpack Public Key & Signature
        size_t offset = sizeof(pqc_gnss::NavigationMessage);
        std::vector<uint8_t> public_key(
            rx_buffer.begin() + offset,
            rx_buffer.begin() + offset + pqc_gnss::config::MOCK_PQC_PUBKEY_SIZE
        );
        offset += pqc_gnss::config::MOCK_PQC_PUBKEY_SIZE;

        std::vector<uint8_t> signature(
            rx_buffer.begin() + offset,
            rx_buffer.begin() + offset + pqc_gnss::config::MOCK_PQC_SIGNATURE_SIZE
        );

        std::vector<uint8_t> payload = pqc_gnss::serialize_nav_message(nav_msg);

        // 3. Post-Quantum Cryptographic Signature Verification
        bool sig_valid = pqc_gnss::PQCCryptoEngine::verify(payload, signature, public_key, nav_msg.satellite_id);
        if (!sig_valid) {
            std::cout << "[❌ INVALID SIGNATURE] Satellite PRN: " << nav_msg.satellite_id
                      << " | Seq: " << nav_msg.sequence_number
                      << " | PQC signature authentication FAILED!\n";
            continue;
        }

        // 4. Anti-Replay Verification
        uint64_t current_time_ns = pqc_gnss::get_current_epoch_ns();
        pqc_gnss::VerificationStatus replay_status = replay_guard.validate(nav_msg, current_time_ns);

        if (replay_status == pqc_gnss::VerificationStatus::REPLAY_DETECTED_OLD_TIMESTAMP) {
            std::cout << "[⚠️ REPLAY DETECTED] Satellite PRN: " << nav_msg.satellite_id
                      << " | Seq: " << nav_msg.sequence_number
                      << " | Packet rejected: Expired or stale timestamp!\n";
            continue;
        } else if (replay_status == pqc_gnss::VerificationStatus::REPLAY_DETECTED_DUPLICATE_SEQUENCE) {
            std::cout << "[⚠️ REPLAY DETECTED] Satellite PRN: " << nav_msg.satellite_id
                      << " | Seq: " << nav_msg.sequence_number
                      << " | Packet rejected: Duplicate sequence or nonce reused!\n";
            continue;
        }

        // 5. Successful Authenticated GNSS Message
        std::cout << "[✅ AUTHENTICATED FIX] "
                  << "SV PRN: " << std::setw(2) << nav_msg.satellite_id
                  << " | Seq: #" << std::setw(4) << nav_msg.sequence_number
                  << " | Lat: " << std::fixed << std::setprecision(5) << nav_msg.coordinates.latitude
                  << " | Lon: " << std::fixed << std::setprecision(5) << nav_msg.coordinates.longitude
                  << " | Alt: " << std::fixed << std::setprecision(1) << nav_msg.coordinates.altitude << "m"
                  << " | Sig: VERIFIED (" << pqc_gnss::config::PQC_SIGNATURE_SCHEME << ")\n";
    }

    close(sock);
    return 0;
}
