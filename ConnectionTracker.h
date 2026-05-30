#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>

// Identifies a TCP connection (bidirectional: always stored with lower tuple first)
struct TcpFlowKey
{
    std::string srcIp;
    uint16_t    srcPort;
    std::string dstIp;
    uint16_t    dstPort;

    bool operator==(const TcpFlowKey& o) const
    {
        return srcIp == o.srcIp && srcPort == o.srcPort &&
            dstIp == o.dstIp && dstPort == o.dstPort;
    }
};

struct TcpFlowKeyHash
{
    size_t operator()(const TcpFlowKey& k) const noexcept
    {
        // FNV-1a-inspired combination
        size_t h = 14695981039346656037ULL;
        auto mix = [&](size_t v) { h ^= v; h *= 1099511628211ULL; };
        std::hash<std::string> sh;
        std::hash<uint16_t>    ph;
        mix(sh(k.srcIp));
        mix(ph(k.srcPort));
        mix(sh(k.dstIp));
        mix(ph(k.dstPort));
        return h;
    }
};

// Per-direction state for one half of a TCP connection
struct TcpDirectionState
{
    uint32_t nextSeq = 0;   // next expected SEQ number this side should send
    uint32_t lastAck = 0;   // most recent ACK this side has acknowledged
    bool     seenFirst = false;
};

// Tracks the most recent TCP SEQ/ACK state for every observed flow.
// Thread-safe.
class ConnectionTracker
{
public:
    // Feed a captured TCP segment so the tracker can update its state.
    // rawFrame must be a complete Ethernet/IPv4/TCP frame.
    void observe(const uint8_t* rawFrame, int len);

    // Retrieve the current next-SEQ for the given direction.
    // Returns false if no state has been observed for this flow yet.
    bool getNextSeq(const TcpFlowKey& key, uint32_t& outNextSeq) const;

    // Retrieve the last-ACK seen from the given direction.
    bool getLastAck(const TcpFlowKey& key, uint32_t& outLastAck) const;

private:
    mutable std::mutex m_lock;
    std::unordered_map<TcpFlowKey, TcpDirectionState, TcpFlowKeyHash> m_states;

    static bool parseTcpHeader(
        const uint8_t* frame, int len,
        std::string& outSrcIp, uint16_t& outSrcPort,
        std::string& outDstIp, uint16_t& outDstPort,
        uint32_t& outSeq, uint32_t& outAck,
        uint8_t& outFlags, size_t& outPayloadLen);
};