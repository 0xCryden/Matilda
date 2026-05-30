#include "ConnectionTracker.h"
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <cstring>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::string ipToString(const uint8_t* b)
{
    char buf[20];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

static uint16_t readU16BE(const uint8_t* b) { return (uint16_t)((b[0] << 8) | b[1]); }
static uint32_t readU32BE(const uint8_t* b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// ---------------------------------------------------------------------------
// Parse Ethernet/IPv4/TCP frame into key fields.
// Returns false if the frame is not a valid IPv4/TCP packet.
// ---------------------------------------------------------------------------
/*static*/
bool ConnectionTracker::parseTcpHeader(
    const uint8_t* frame, int len,
    std::string& outSrcIp, uint16_t& outSrcPort,
    std::string& outDstIp, uint16_t& outDstPort,
    uint32_t& outSeq, uint32_t& outAck,
    uint8_t& outFlags, size_t& outPayloadLen)
{
    const size_t kEthLen = 14;
    if (len < (int)(kEthLen + 20)) return false;

    uint16_t ethType = readU16BE(frame + 12);
    if (ethType != 0x0800) return false;

    const uint8_t* ip = frame + kEthLen;
    uint8_t ihl = (ip[0] & 0x0F) * 4u;
    if (ihl < 20 || len < (int)(kEthLen + ihl + 20)) return false;
    if (ip[9] != 6) return false; // not TCP

    outSrcIp = ipToString(ip + 12);
    outDstIp = ipToString(ip + 16);

    const uint8_t* tcp = ip + ihl;
    outSrcPort = readU16BE(tcp + 0);
    outDstPort = readU16BE(tcp + 2);
    outSeq = readU32BE(tcp + 4);
    outAck = readU32BE(tcp + 8);
    outFlags = tcp[13];

    uint8_t dataOff = (tcp[12] >> 4) & 0x0F;
    size_t tcpHdrLen = (dataOff < 5) ? 20u : (size_t)dataOff * 4;
    size_t totalIpLen = readU16BE(ip + 2);
    size_t transportLen = (totalIpLen > ihl) ? totalIpLen - ihl : 0;
    outPayloadLen = (transportLen > tcpHdrLen) ? transportLen - tcpHdrLen : 0;

    return true;
}

// ---------------------------------------------------------------------------
// observe — update internal state from a live or captured packet
// ---------------------------------------------------------------------------
void ConnectionTracker::observe(const uint8_t* rawFrame, int len)
{
    std::string srcIp, dstIp;
    uint16_t srcPort = 0, dstPort = 0;
    uint32_t seq = 0, ack = 0;
    uint8_t  flags = 0;
    size_t   payloadLen = 0;

    if (!parseTcpHeader(rawFrame, len, srcIp, srcPort, dstIp, dstPort, seq, ack, flags, payloadLen))
        return;

    // SYN counts as 1 byte, FIN counts as 1 byte
    bool isSyn = (flags & 0x02) != 0;
    bool isFin = (flags & 0x01) != 0;
    uint32_t seqAdv = (uint32_t)payloadLen + (isSyn ? 1u : 0u) + (isFin ? 1u : 0u);

    TcpFlowKey key{ srcIp, srcPort, dstIp, dstPort };

    std::lock_guard<std::mutex> lk(m_lock);
    auto& state = m_states[key];
    if (!state.seenFirst)
    {
        state.nextSeq = seq + seqAdv;
        state.lastAck = ack;
        state.seenFirst = true;
    }
    else
    {
        // Advance if this segment is newer (handles wrap-around approximately)
        int32_t diff = (int32_t)(seq - (state.nextSeq - seqAdv));
        if (diff >= 0)
        {
            state.nextSeq = seq + seqAdv;
            state.lastAck = ack;
        }
    }
}

// ---------------------------------------------------------------------------
bool ConnectionTracker::getNextSeq(const TcpFlowKey& key, uint32_t& outNextSeq) const
{
    std::lock_guard<std::mutex> lk(m_lock);
    auto it = m_states.find(key);
    if (it == m_states.end() || !it->second.seenFirst) return false;
    outNextSeq = it->second.nextSeq;
    return true;
}

bool ConnectionTracker::getLastAck(const TcpFlowKey& key, uint32_t& outLastAck) const
{
    std::lock_guard<std::mutex> lk(m_lock);
    auto it = m_states.find(key);
    if (it == m_states.end() || !it->second.seenFirst) return false;
    outLastAck = it->second.lastAck;
    return true;
}