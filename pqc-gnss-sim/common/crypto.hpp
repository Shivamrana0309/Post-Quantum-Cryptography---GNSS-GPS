#pragma once

#include "types.hpp"
#include "config.hpp"
#include <vector>
#include <cstring>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <iostream>
#include <iomanip>

namespace pqc_gnss {

// Serialize NavigationMessage into a flat byte vector
inline std::vector<uint8_t> serialize_nav_message(const NavigationMessage& msg) {
    std::vector<uint8_t> buffer(sizeof(NavigationMessage));
    std::memcpy(buffer.data(), &msg, sizeof(NavigationMessage));
    return buffer;
}

// Deserialize NavigationMessage from a byte pointer
inline bool deserialize_nav_message(const uint8_t* data, size_t size, NavigationMessage& out_msg) {
    if (size < sizeof(NavigationMessage)) {
        return false;
    }
    std::memcpy(&out_msg, data, sizeof(NavigationMessage));
    return true;
}

// PQC Signature Engine Interface (Simulates NIST ML-DSA / Dilithium signing)
class PQCCryptoEngine {
public:
    static std::vector<uint8_t> generate_public_key(uint32_t satellite_id) {
        std::vector<uint8_t> pk(config::MOCK_PQC_PUBKEY_SIZE, 0xAA);
        // Tag with satellite ID for identification
        std::memcpy(pk.data(), &satellite_id, sizeof(satellite_id));
        return pk;
    }

    // Sign payload using satellite's PQC key
    static std::vector<uint8_t> sign(const std::vector<uint8_t>& payload, uint32_t satellite_id) {
        std::vector<uint8_t> signature(config::MOCK_PQC_SIGNATURE_SIZE, 0);

        // Fill signature simulation with hash/tagging of payload
        uint64_t hash = 14695981039346656037ULL; // FNV-1a hash
        for (uint8_t byte : payload) {
            hash ^= byte;
            hash *= 1099511628211ULL;
        }

        std::memcpy(signature.data(), &hash, sizeof(hash));
        std::memcpy(signature.data() + sizeof(hash), &satellite_id, sizeof(satellite_id));

        // Pattern padding representing post-quantum lattice signature structure
        for (size_t i = sizeof(hash) + sizeof(satellite_id); i < signature.size(); ++i) {
            signature[i] = static_cast<uint8_t>((hash + i) % 256);
        }

        return signature;
    }

    // Verify post-quantum signature against payload and public key
    static bool verify(const std::vector<uint8_t>& payload,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key,
                       uint32_t satellite_id) {
        if (signature.size() != config::MOCK_PQC_SIGNATURE_SIZE ||
            public_key.size() != config::MOCK_PQC_PUBKEY_SIZE) {
            return false;
        }

        // Verify public key ownership
        uint32_t pk_satellite_id = 0;
        std::memcpy(&pk_satellite_id, public_key.data(), sizeof(pk_satellite_id));
        if (pk_satellite_id != satellite_id) {
            return false;
        }

        // Recompute hash
        uint64_t expected_hash = 14695981039346656037ULL;
        for (uint8_t byte : payload) {
            expected_hash ^= byte;
            expected_hash *= 1099511628211ULL;
        }

        uint64_t sig_hash = 0;
        uint32_t sig_satellite_id = 0;
        std::memcpy(&sig_hash, signature.data(), sizeof(sig_hash));
        std::memcpy(&sig_satellite_id, signature.data() + sizeof(sig_hash), sizeof(sig_satellite_id));

        return (sig_hash == expected_hash && sig_satellite_id == satellite_id);
    }
};

// Anti-Replay Guard: protects receiver from stale or replayed messages
class AntiReplayGuard {
private:
    std::mutex mutex_;
    uint64_t last_seen_sequence_{0};
    std::unordered_set<uint64_t> seen_nonces_;

public:
    VerificationStatus validate(const NavigationMessage& msg, uint64_t current_time_ns) {
        std::lock_guard<std::mutex> lock(mutex_);

        // 1. Timestamp Freshness Check
        if (current_time_ns > msg.timestamp_ns) {
            uint64_t age = current_time_ns - msg.timestamp_ns;
            if (age > config::MAX_CLOCK_DRIFT_NS) {
                return VerificationStatus::REPLAY_DETECTED_OLD_TIMESTAMP;
            }
        } else {
            uint64_t future_drift = msg.timestamp_ns - current_time_ns;
            if (future_drift > config::MAX_CLOCK_DRIFT_NS) {
                return VerificationStatus::REPLAY_DETECTED_OLD_TIMESTAMP;
            }
        }

        // 2. Monotonic Sequence and Nonce Check
        if (msg.sequence_number <= last_seen_sequence_ && last_seen_sequence_ != 0) {
            return VerificationStatus::REPLAY_DETECTED_DUPLICATE_SEQUENCE;
        }

        if (seen_nonces_.find(msg.nonce) != seen_nonces_.end()) {
            return VerificationStatus::REPLAY_DETECTED_DUPLICATE_SEQUENCE;
        }

        // Cache sequence and nonce
        last_seen_sequence_ = msg.sequence_number;
        seen_nonces_.insert(msg.nonce);

        if (seen_nonces_.size() > config::REPLAY_CACHE_WINDOW_SIZE) {
            seen_nonces_.clear();
            seen_nonces_.insert(msg.nonce);
        }

        return VerificationStatus::SUCCESS;
    }
};

inline uint64_t get_current_epoch_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace pqc_gnss
