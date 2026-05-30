#pragma once

#include <vector>
#include <string>
#include <mutex>
#include <cstdint>
#include "RawPacket.h"

// Thread-safe storage for captured raw packets and associated metadata.
class PacketStore {
public:
    PacketStore();
    ~PacketStore();

    // Append a captured RawPacket (takes ownership of p)
    void appendPacket(pcpp::RawPacket* p, const std::vector<std::string>& meta);

    // Append an outgoing frame (copy of bytes) with metadata
    void appendOutgoing(const std::vector<uint8_t>& frame, const std::vector<std::string>& meta);

    size_t getCount() const;
    bool getPacketBytes(size_t index, std::vector<uint8_t>& out) const;
    bool getMeta(size_t index, std::vector<std::string>& out) const;

    // Return a new RawPacket allocated by caller; nullptr on error
    pcpp::RawPacket* clonePacket(size_t index) const;

private:
    mutable std::mutex m_lock;
    pcpp::RawPacketVector m_packets;
    std::vector<std::vector<std::string>> m_meta;
};
