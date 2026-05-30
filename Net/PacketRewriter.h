#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <functional>

class ConnectionTracker;

class PacketRewriter {
public:
    // Rewrite original frame bytes with optional payload and overrides, adjust checksums/seq/ack using connTracker,
    // and call sendFunc(out) to transmit the rewritten bytes. Returns true on success; on failure sets errOut if provided.
    static bool sendWithOverrides(
        const std::vector<uint8_t>& origFrame,
        const std::vector<uint8_t>& payload,
        const std::string& protoOverride,
        const std::string& srcIpOverride,
        uint16_t srcPortOverride,
        const std::string& dstIpOverride,
        uint16_t dstPortOverride,
        ConnectionTracker* connTracker,
        const std::function<bool(const std::vector<uint8_t>&)>& sendFunc,
        std::string* errOut = nullptr);
};
