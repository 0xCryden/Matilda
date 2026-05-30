#include "PacketRewriter.h"
#include "ChecksumUtils.h"
#include "..\ConnectionTracker.h"

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>

bool PacketRewriter::sendWithOverrides(
    const std::vector<uint8_t>& origFrame,
    const std::vector<uint8_t>& payload,
    const std::string& protoOverride,
    const std::string& srcIpOverride,
    uint16_t srcPortOverride,
    const std::string& dstIpOverride,
    uint16_t dstPortOverride,
    ConnectionTracker* connTracker,
    const std::function<bool(const std::vector<uint8_t>&)>& sendFunc,
    std::string* errOut)
{
    try {
        if (!sendFunc) { if (errOut) *errOut = "Send function not provided"; return false; }
        if (origFrame.empty()) { if (errOut) *errOut = "Original frame empty"; return false; }

        std::vector<uint8_t> data = origFrame;

        // Ethernet + IPv4 guard
        const size_t kEthHdrLen = 14;
        if (data.size() < kEthHdrLen + 20) { if (errOut) *errOut = "Packet too small for Ethernet + IPv4"; return false; }
        uint16_t ethType = (uint16_t)((data[12] << 8) | data[13]);
        if (ethType != 0x0800) { if (errOut) *errOut = "Only IPv4 packets supported"; return false; }

        size_t ipOffset = kEthHdrLen;
        uint8_t ihl = data[ipOffset] & 0x0F;
        size_t ipHeaderLen = (size_t)ihl * 4;
        if (ipHeaderLen < 20 || data.size() < ipOffset + ipHeaderLen) { if (errOut) *errOut = "Invalid IPv4 header"; return false; }

        uint8_t protocol = data[ipOffset + 9];
        size_t transportOffset = ipOffset + ipHeaderLen;
        if (data.size() < transportOffset) { if (errOut) *errOut = "Invalid transport offset"; return false; }

        size_t transHeaderLen = 0; size_t payloadOffset = 0;
        if (protocol == 6) { // TCP
            if (data.size() < transportOffset + 20) { if (errOut) *errOut = "TCP header truncated"; return false; }
            uint8_t tcpDataOffset = (data[transportOffset + 12] >> 4) & 0x0F;
            transHeaderLen = (size_t)tcpDataOffset * 4; if (transHeaderLen < 20) transHeaderLen = 20;
            payloadOffset = transportOffset + transHeaderLen;
        } else if (protocol == 17) { // UDP
            if (data.size() < transportOffset + 8) { if (errOut) *errOut = "UDP header truncated"; return false; }
            transHeaderLen = 8; payloadOffset = transportOffset + transHeaderLen;
        } else {
            if (errOut) *errOut = "Unsupported transport protocol for custom send"; return false; }

        if (!protoOverride.empty()) {
            if ((protoOverride == "TCP" && protocol != 6) || (protoOverride == "UDP" && protocol != 17)) {
                if (errOut) *errOut = "Protocol override does not match original packet"; return false; }
        }

        std::vector<uint8_t> newPayload;
        if (payload.empty()) {
            if (data.size() > payloadOffset)
                newPayload.assign(data.begin() + payloadOffset, data.end());
        } else { newPayload = payload; }

        std::vector<uint8_t> out;
        out.insert(out.end(), data.begin(), data.begin() + payloadOffset);
        out.insert(out.end(), newPayload.begin(), newPayload.end());

        // Apply IP overrides
        if (!srcIpOverride.empty()) {
            in_addr a{};
            if (inet_pton(AF_INET, srcIpOverride.c_str(), &a) != 1) { if (errOut) *errOut = "Invalid source IP override"; return false; }
            if (out.size() >= ipOffset + 16)
                memcpy(&out[ipOffset + 12], &a.S_un.S_addr, 4);
        }
        if (!dstIpOverride.empty()) {
            in_addr a{};
            if (inet_pton(AF_INET, dstIpOverride.c_str(), &a) != 1) { if (errOut) *errOut = "Invalid destination IP override"; return false; }
            if (out.size() >= ipOffset + 20)
                memcpy(&out[ipOffset + 16], &a.S_un.S_addr, 4);
        }

        // Apply port overrides
        if (srcPortOverride != 0) {
            if (out.size() < transportOffset + 2) { if (errOut) *errOut = "Frame too small for source port override"; return false; }
            write_u16_be(&out[transportOffset], srcPortOverride);
        }
        if (dstPortOverride != 0) {
            if (out.size() < transportOffset + 4) { if (errOut) *errOut = "Frame too small for destination port override"; return false; }
            write_u16_be(&out[transportOffset + 2], dstPortOverride);
        }

        // TCP SEQ/ACK correction (uses connTracker)
        if (protocol == 6 && out.size() >= transportOffset + 20) {
            char srcIpBuf[20], dstIpBuf[20];
            auto sip = &out[ipOffset + 12];
            auto dip = &out[ipOffset + 16];
            snprintf(srcIpBuf, sizeof(srcIpBuf), "%u.%u.%u.%u", sip[0], sip[1], sip[2], sip[3]);
            snprintf(dstIpBuf, sizeof(dstIpBuf), "%u.%u.%u.%u", dip[0], dip[1], dip[2], dip[3]);

            uint16_t sport = read_u16_be(&out[transportOffset + 0]);
            uint16_t dport = read_u16_be(&out[transportOffset + 2]);

            TcpFlowKey fwdKey{ srcIpBuf, sport, dstIpBuf, dport };
            TcpFlowKey revKey{ dstIpBuf, dport, srcIpBuf, sport };

            uint32_t nextSeq = 0; uint32_t lastAck = 0;
            bool haveSeq = false, haveAck = false;
            if (connTracker) {
                haveSeq = connTracker->getNextSeq(fwdKey, nextSeq);
                haveAck = connTracker->getLastAck(fwdKey, lastAck);
                if (!haveSeq) {
                    uint32_t peerAck = 0; if (connTracker->getLastAck(revKey, peerAck)) { nextSeq = peerAck; haveSeq = true; }
                }
                if (!haveAck) {
                    uint32_t peerSeq = 0; if (connTracker->getNextSeq(revKey, peerSeq)) { lastAck = peerSeq; haveAck = true; }
                }
            }
            if (haveSeq) write_u32_be(&out[transportOffset + 4], nextSeq);
            if (haveAck) write_u32_be(&out[transportOffset + 8], lastAck);
            out[transportOffset + 14] = 0xFF; out[transportOffset + 15] = 0xFF;
        }

        // IPv4 total length
        uint16_t newIpTotalLen = (uint16_t)(ipHeaderLen + transHeaderLen + newPayload.size());
        if (out.size() < ipOffset + 4) { if (errOut) *errOut = "Frame too small to update IP length"; return false; }
        write_u16_be(&out[ipOffset + 2], newIpTotalLen);

        // IPv4 header checksum
        if (out.size() < ipOffset + ipHeaderLen) { if (errOut) *errOut = "Frame too small for IP checksum"; return false; }
        out[ipOffset + 10] = 0; out[ipOffset + 11] = 0;
        write_u16_be(&out[ipOffset + 10], ones_complement_checksum(&out[ipOffset], ipHeaderLen));

        // Transport checksum via pseudo-header
        if (out.size() < ipOffset + 20) { if (errOut) *errOut = "IPv4 header too small for pseudo-header extraction"; return false; }
        uint8_t srcIpBytes[4], dstIpBytes[4];
        memcpy(srcIpBytes, &out[ipOffset + 12], 4);
        memcpy(dstIpBytes, &out[ipOffset + 16], 4);
        uint16_t transportLen = (uint16_t)(transHeaderLen + newPayload.size());

        auto buildPseudo = [&](std::vector<uint8_t>& cbuf) {
            cbuf.insert(cbuf.end(), srcIpBytes, srcIpBytes + 4);
            cbuf.insert(cbuf.end(), dstIpBytes, dstIpBytes + 4);
            cbuf.push_back(0); cbuf.push_back(protocol);
            uint8_t tlenb[2]; write_u16_be(tlenb, transportLen); cbuf.push_back(tlenb[0]); cbuf.push_back(tlenb[1]);
        };

        if (protocol == 6) {
            size_t csumOff = transportOffset + 16;
            if (out.size() < csumOff + 2) { if (errOut) *errOut = "Frame too small for TCP checksum"; return false; }
            out[csumOff] = 0; out[csumOff + 1] = 0;
            std::vector<uint8_t> cbuf; buildPseudo(cbuf);
            cbuf.insert(cbuf.end(), out.begin() + transportOffset, out.begin() + transportOffset + transHeaderLen);
            cbuf.insert(cbuf.end(), newPayload.begin(), newPayload.end());
            write_u16_be(&out[csumOff], ones_complement_checksum(cbuf.data(), cbuf.size()));
        } else if (protocol == 17) {
            size_t lenOff = transportOffset + 4; size_t csumOff = transportOffset + 6;
            if (out.size() < csumOff + 2) { if (errOut) *errOut = "Frame too small for UDP header"; return false; }
            write_u16_be(&out[lenOff], transportLen);
            out[csumOff] = 0; out[csumOff + 1] = 0;
            std::vector<uint8_t> cbuf; buildPseudo(cbuf);
            cbuf.insert(cbuf.end(), out.begin() + transportOffset, out.begin() + transportOffset + transHeaderLen);
            cbuf.insert(cbuf.end(), newPayload.begin(), newPayload.end());
            write_u16_be(&out[csumOff], ones_complement_checksum(cbuf.data(), cbuf.size()));
        }

        // Send via provided sendFunc
        if (!sendFunc(out)) { if (errOut) *errOut = "sendFunc failed"; return false; }

        return true;
    }
    catch (const std::exception& ex) { if (errOut) *errOut = std::string("exception: ") + ex.what(); return false; }
    catch (...) { if (errOut) *errOut = "unknown exception"; return false; }
}
