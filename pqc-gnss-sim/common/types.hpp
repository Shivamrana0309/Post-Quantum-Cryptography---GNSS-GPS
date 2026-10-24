#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <chrono>

namespace pqc_gnss {

// GNSS Coordinates (WGS84 representation)
struct GNSSCoordinates {
    double latitude{0.0};   // Degrees (-90.0 to +90.0)
    double longitude{0.0};  // Degrees (-180.0 to +180.0)
    double altitude{0.0};   // Meters above mean sea level
};

// Raw Navigation Message payload broadcast by GNSS satellites
struct NavigationMessage {
    uint32_t satellite_id{0};       // PRN identifier (e.g. SV 1-32)
    uint64_t timestamp_ns{0};       // Epoch timestamp in nanoseconds
    uint64_t sequence_number{0};     // Monotonically increasing sequence to prevent replay
    uint64_t nonce{0};               // Cryptographic pseudo-random nonce
    GNSSCoordinates coordinates{};   // Satellite orbital position / fix
    double pseudorange{0.0};        // Pseudorange measurement in meters
    char ephemeris_hash[32]{};       // Integrity hash of ephemeris parameters
};

// Post-Quantum Secure Packet wrapping the navigation payload and signature
struct SecureGNSSPacket {
    NavigationMessage nav_msg;
    std::string algorithm{"ML-DSA-65 (Dilithium3)"}; // Standard NIST PQC digital signature algorithm
    std::vector<uint8_t> signature;                  // Post-quantum signature bytes
    std::vector<uint8_t> public_key;                 // Satellite public key or identifier
};

// Verification status codes for receiver evaluation
enum class VerificationStatus {
    SUCCESS,
    REPLAY_DETECTED_OLD_TIMESTAMP,
    REPLAY_DETECTED_DUPLICATE_SEQUENCE,
    INVALID_SIGNATURE,
    CORRUPTED_PAYLOAD
};

} // namespace pqc_gnss
