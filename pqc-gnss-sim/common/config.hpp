#pragma once

#include <cstdint>
#include <string>

namespace pqc_gnss {

namespace config {
    // Network communication configuration for simulation (UDP broadcast)
    constexpr const char* DEFAULT_BROADCAST_IP = "127.0.0.1";
    constexpr uint16_t DEFAULT_BROADCAST_PORT = 9050;

    // Simulation transmission timings
    constexpr uint32_t TRANSMISSION_INTERVAL_MS = 1000; // 1 Hz broadcast rate

    // Anti-replay security parameters
    constexpr uint64_t MAX_CLOCK_DRIFT_NS = 5000000000ULL; // 5.0 seconds maximum allowable drift
    constexpr size_t REPLAY_CACHE_WINDOW_SIZE = 1024;       // Number of recent sequences to cache
    
    // Cryptographic parameters
    constexpr const char* PQC_SIGNATURE_SCHEME = "ML-DSA-65"; // Dilithium3 equivalent
    constexpr size_t MOCK_PQC_SIGNATURE_SIZE = 3309;          // ML-DSA-65 typical signature size (bytes)
    constexpr size_t MOCK_PQC_PUBKEY_SIZE = 1952;             // ML-DSA-65 public key size (bytes)
}

} // namespace pqc_gnss
