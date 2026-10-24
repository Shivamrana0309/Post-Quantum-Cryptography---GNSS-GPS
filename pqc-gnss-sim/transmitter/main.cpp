#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../common/types.hpp"
#include "../common/config.hpp"
#include "../common/crypto.hpp"

int main(int argc, char* argv[]) {
    uint32_t satellite_prn = 12; // Example GPS SV PRN 12
    std::string target_ip = pqc_gnss::config::DEFAULT_BROADCAST_IP;
    uint16_t target_port = pqc_gnss::config::DEFAULT_BROADCAST_PORT;

    if (argc > 1) {
        satellite_prn = static_cast<uint32_t>(std::stoi(argv[1]));
    }

    std::cout << "====================================================\n";
    std::cout << "       PQC GNSS SATELLITE TRANSMITTER SIMULATOR     \n";
    std::cout << "====================================================\n";
    std::cout << "[*] Satellite PRN ID : " << satellite_prn << "\n";
    std::cout << "[*] PQC Signature    : " << pqc_gnss::config::PQC_SIGNATURE_SCHEME << "\n";
    std::cout << "[*] Target Endpoint  : " << target_ip << ":" << target_port << "\n";
    std::cout << "[*] Anti-Replay Nonce: Enabled (Monotonic Counters)\n";
    std::cout << "----------------------------------------------------\n";

    // Setup UDP broadcast socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[!] Error creating UDP socket.\n";
        return 1;
    }

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr);

    // Generate Post-Quantum public key for this satellite
    std::vector<uint8_t> public_key = pqc_gnss::PQCCryptoEngine::generate_public_key(satellite_prn);

    // Initial simulated satellite orbit trajectory (orbital movement)
    double base_lat = 37.7749;
    double base_lon = -122.4194;
    double base_alt = 20200000.0; // ~20,200 km (MEO GPS orbit)

    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> nonce_dist;

    uint64_t sequence_number = 1;

    std::cout << "[+] Transmitter started. Broadcasting signed GNSS telemetry...\n";

    while (true) {
        pqc_gnss::NavigationMessage nav_msg{};
        nav_msg.satellite_id = satellite_prn;
        nav_msg.timestamp_ns = pqc_gnss::get_current_epoch_ns();
        nav_msg.sequence_number = sequence_number++;
        nav_msg.nonce = nonce_dist(rng);

        // Orbital displacement simulation
        nav_msg.coordinates.latitude = base_lat + (sequence_number * 0.001);
        nav_msg.coordinates.longitude = base_lon + (sequence_number * 0.002);
        nav_msg.coordinates.altitude = base_alt;
        nav_msg.pseudorange = 20200150.0 + (sequence_number % 50);

        // Serialize payload for signing
        std::vector<uint8_t> payload = pqc_gnss::serialize_nav_message(nav_msg);

        // Sign using Post-Quantum Cryptography algorithm (ML-DSA)
        std::vector<uint8_t> signature = pqc_gnss::PQCCryptoEngine::sign(payload, satellite_prn);

        // Assemble wire packet: [Payload (NavigationMessage)] + [Public Key] + [Signature]
        std::vector<uint8_t> packet;
        packet.insert(packet.end(), payload.begin(), payload.end());
        packet.insert(packet.end(), public_key.begin(), public_key.end());
        packet.insert(packet.end(), signature.begin(), signature.end());

        // Transmit over UDP
        ssize_t bytes_sent = sendto(sock, packet.data(), packet.size(), 0,
                                    reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr));

        if (bytes_sent > 0) {
            std::cout << "[TX] Sent Packet #" << nav_msg.sequence_number
                      << " | PRN: " << nav_msg.satellite_id
                      << " | Lat: " << nav_msg.coordinates.latitude
                      << " | Lon: " << nav_msg.coordinates.longitude
                      << " | PQC Sig Size: " << signature.size() << " bytes"
                      << " | Total Size: " << bytes_sent << " bytes\n";
        } else {
            std::cerr << "[!] Failed to broadcast packet.\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(pqc_gnss::config::TRANSMISSION_INTERVAL_MS));
    }

    close(sock);
    return 0;
}
