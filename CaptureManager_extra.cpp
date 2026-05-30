#include <WinSock2.h>
#include <Ws2tcpip.h>
#include "CaptureManager.h"
#include "Net/ChecksumUtils.h"
#include <ctime>
#include <sstream>

// ---------------------------------------------------------------------------
bool CaptureManager::sendCapturedPacket(size_t index)
{
    if (!m_currentDevice || index >= m_capturedPackets.size())
        return false;

    pcpp::RawPacketVector tmp;
    try { tmp.pushBack(new pcpp::RawPacket(*m_capturedPackets.at((int)index))); }
    catch (...) { return false; }

    return m_currentDevice->sendPackets(tmp) == 1;
}

// ---------------------------------------------------------------------------
bool CaptureManager::sendCapturedPacketWithPayload(
    size_t index,
    const std::vector<uint8_t>& payload,
    const std::string& protoOverride,
    const std::string& srcIpOverride,
    uint16_t           srcPortOverride,
    const std::string& dstIpOverride,
    uint16_t           dstPortOverride,
    std::string* errOut)
{
    try {
        // Sending is only supported while capture (and therefore the device) is active.
        if (!m_running || !m_currentDevice)
        {
            if (errOut) *errOut = "Capture must be running to send packets";
            return false;
        }
        if (index >= m_capturedPackets.size())
        {
            if (errOut) *errOut = "Invalid packet index";
            return false;
        }

        pcpp::RawPacket* orig = m_capturedPackets.at((int)index);
        if (!orig) { if (errOut) *errOut = "Original packet missing"; return false; }

        const uint8_t* origData = orig->getRawData();
        int            origLen = orig->getRawDataLen();
        if (origLen <= 0) { if (errOut) *errOut = "Original packet has zero length"; return false; }

        std::vector<uint8_t> data(origData, origData + origLen);

        // --- Ethernet / IPv4 guard ---
        const size_t kEthHdrLen = 14;
        if (data.size() < kEthHdrLen + 20)
        {
            if (errOut) *errOut = "Packet too small for Ethernet + IPv4";
            return false;
        }

        uint16_t ethType = (uint16_t)((data[12] << 8) | data[13]);
        if (ethType != 0x0800)
        {
            if (errOut) *errOut = "Only IPv4 packets are supported for custom send";
            return false;
        }

        size_t  ipOffset = kEthHdrLen;
        uint8_t ihl = data[ipOffset] & 0x0F;
        size_t  ipHeaderLen = (size_t)ihl * 4;
        if (ipHeaderLen < 20 || data.size() < ipOffset + ipHeaderLen)
        {
            if (errOut) *errOut = "Invalid IPv4 header"; return false;
        }

        uint8_t protocol = data[ipOffset + 9];

        size_t transportOffset = ipOffset + ipHeaderLen;
        if (data.size() < transportOffset)
        {
            if (errOut) *errOut = "Invalid transport offset"; return false;
        }

        // Determine transport header / payload boundaries
        size_t transHeaderLen = 0;
        size_t payloadOffset = 0;

        if (protocol == 6) // TCP
        {
            if (data.size() < transportOffset + 20)
            {
                if (errOut) *errOut = "TCP header truncated"; return false;
            }
            uint8_t tcpDataOffset = (data[transportOffset + 12] >> 4) & 0x0F;
            transHeaderLen = (size_t)tcpDataOffset * 4;
            if (transHeaderLen < 20) transHeaderLen = 20;
            payloadOffset = transportOffset + transHeaderLen;
        }
        else if (protocol == 17) // UDP
        {
            if (data.size() < transportOffset + 8)
            {
                if (errOut) *errOut = "UDP header truncated"; return false;
            }
            transHeaderLen = 8;
            payloadOffset = transportOffset + transHeaderLen;
        }
        else
        {
            if (errOut) *errOut = "Unsupported transport protocol for custom send";
            return false;
        }

        // Protocol override sanity check
        if (!protoOverride.empty())
        {
            if ((protoOverride == "TCP" && protocol != 6) ||
                (protoOverride == "UDP" && protocol != 17))
            {
                if (errOut) *errOut = "Protocol override does not match original packet";
                return false;
            }
        }

        // Determine payload bytes
        std::vector<uint8_t> newPayload;
        if (payload.empty())
        {
            if (data.size() > payloadOffset)
                newPayload.assign(data.begin() + payloadOffset, data.end());
        }
        else
        {
            newPayload = payload;
        }

        // Build new frame: headers up to payload, then new payload
        std::vector<uint8_t> out;
        out.insert(out.end(), data.begin(), data.begin() + payloadOffset);
        out.insert(out.end(), newPayload.begin(), newPayload.end());

        // --- Apply IP overrides ---
        if (!srcIpOverride.empty())
        {
            in_addr a{};
            if (inet_pton(AF_INET, srcIpOverride.c_str(), &a) != 1)
            {
                if (errOut) *errOut = "Invalid source IP override"; return false;
            }
            if (out.size() >= ipOffset + 16)
                memcpy(&out[ipOffset + 12], &a.S_un.S_addr, 4);
        }
        if (!dstIpOverride.empty())
        {
            in_addr a{};
            if (inet_pton(AF_INET, dstIpOverride.c_str(), &a) != 1)
            {
                if (errOut) *errOut = "Invalid destination IP override"; return false;
            }
            if (out.size() >= ipOffset + 20)
                memcpy(&out[ipOffset + 16], &a.S_un.S_addr, 4);
        }

        // --- Apply port overrides ---
        if (srcPortOverride != 0)
        {
            if (out.size() < transportOffset + 2)
            {
                if (errOut) *errOut = "Frame too small for source port override"; return false;
            }
            write_u16_be(&out[transportOffset], srcPortOverride);
        }
        if (dstPortOverride != 0)
        {
            if (out.size() < transportOffset + 4)
            {
                if (errOut) *errOut = "Frame too small for destination port override"; return false;
            }
            write_u16_be(&out[transportOffset + 2], dstPortOverride);
        }

        // --- TCP SEQ / ACK correction using ConnectionTracker ---
        if (protocol == 6 && out.size() >= transportOffset + 20)
        {
            // Extract current src/dst from the (possibly overridden) frame
            char srcIpBuf[20], dstIpBuf[20];
            auto sip = &out[ipOffset + 12];
            auto dip = &out[ipOffset + 16];
            snprintf(srcIpBuf, sizeof(srcIpBuf), "%u.%u.%u.%u", sip[0], sip[1], sip[2], sip[3]);
            snprintf(dstIpBuf, sizeof(dstIpBuf), "%u.%u.%u.%u", dip[0], dip[1], dip[2], dip[3]);

            uint16_t sport = read_u16_be(&out[transportOffset + 0]);
            uint16_t dport = read_u16_be(&out[transportOffset + 2]);

            // The flow key must match the direction of the original captured packet
            // (i.e. what the sender was transmitting, not the receiver's direction).
            TcpFlowKey fwdKey{ srcIpBuf, sport, dstIpBuf, dport };
            TcpFlowKey revKey{ dstIpBuf, dport, srcIpBuf, sport };

            uint32_t nextSeq = 0;
            uint32_t lastAck = 0;
            bool     haveSeq = m_connTracker.getNextSeq(fwdKey, nextSeq);
            bool     haveAck = m_connTracker.getLastAck(fwdKey, lastAck);

            // Fall back to reverse direction ACK for our SEQ if not available
            if (!haveSeq)
            {
                // Use peer's last-ack as a hint for our next-seq
                uint32_t peerAck = 0;
                if (m_connTracker.getLastAck(revKey, peerAck))
                {
                    nextSeq = peerAck;
                    haveSeq = true;
                }
            }
            if (!haveAck)
            {
                // Use peer's next-seq as our ACK
                uint32_t peerSeq = 0;
                if (m_connTracker.getNextSeq(revKey, peerSeq))
                {
                    lastAck = peerSeq;
                    haveAck = true;
                }
            }

            if (haveSeq) write_u32_be(&out[transportOffset + 4], nextSeq);
            if (haveAck) write_u32_be(&out[transportOffset + 8], lastAck);

            // Generous window so the server won't reject us due to zero-window
            out[transportOffset + 14] = 0xFF;
            out[transportOffset + 15] = 0xFF;
        }

        // --- IPv4 total length ---
        uint16_t newIpTotalLen = (uint16_t)(ipHeaderLen + transHeaderLen + newPayload.size());
        if (out.size() < ipOffset + 4)
        {
            if (errOut) *errOut = "Frame too small to update IP length"; return false;
        }
        write_u16_be(&out[ipOffset + 2], newIpTotalLen);

        // --- IPv4 header checksum ---
        if (out.size() < ipOffset + ipHeaderLen)
        {
            if (errOut) *errOut = "Frame too small for IP checksum"; return false;
        }
        out[ipOffset + 10] = 0; out[ipOffset + 11] = 0;
        write_u16_be(&out[ipOffset + 10], ones_complement_checksum(&out[ipOffset], ipHeaderLen));

        // --- Transport checksum ---
        if (out.size() < ipOffset + 20)
        {
            if (errOut) *errOut = "IPv4 header too small for pseudo-header extraction"; return false;
        }
        uint8_t srcIpBytes[4], dstIpBytes[4];
        memcpy(srcIpBytes, &out[ipOffset + 12], 4);
        memcpy(dstIpBytes, &out[ipOffset + 16], 4);
        uint16_t transportLen = (uint16_t)(transHeaderLen + newPayload.size());

        auto buildPseudo = [&](std::vector<uint8_t>& cbuf)
            {
                cbuf.insert(cbuf.end(), srcIpBytes, srcIpBytes + 4);
                cbuf.insert(cbuf.end(), dstIpBytes, dstIpBytes + 4);
                cbuf.push_back(0);
                cbuf.push_back(protocol);
                uint8_t tlenb[2]; write_u16_be(tlenb, transportLen);
                cbuf.push_back(tlenb[0]); cbuf.push_back(tlenb[1]);
            };

        if (protocol == 6) // TCP
        {
            size_t csumOff = transportOffset + 16;
            if (out.size() < csumOff + 2)
            {
                if (errOut) *errOut = "Frame too small for TCP checksum"; return false;
            }
            out[csumOff] = 0; out[csumOff + 1] = 0;

            std::vector<uint8_t> cbuf;
            buildPseudo(cbuf);
            cbuf.insert(cbuf.end(), out.begin() + transportOffset,
                out.begin() + transportOffset + transHeaderLen);
            cbuf.insert(cbuf.end(), newPayload.begin(), newPayload.end());
            write_u16_be(&out[csumOff], ones_complement_checksum(cbuf.data(), cbuf.size()));
        }
        else if (protocol == 17) // UDP
        {
            size_t lenOff = transportOffset + 4;
            size_t csumOff = transportOffset + 6;
            if (out.size() < csumOff + 2)
            {
                if (errOut) *errOut = "Frame too small for UDP header"; return false;
            }
            write_u16_be(&out[lenOff], transportLen);
            out[csumOff] = 0; out[csumOff + 1] = 0;

            std::vector<uint8_t> cbuf;
            buildPseudo(cbuf);
            cbuf.insert(cbuf.end(), out.begin() + transportOffset,
                out.begin() + transportOffset + transHeaderLen);
            cbuf.insert(cbuf.end(), newPayload.begin(), newPayload.end());
            write_u16_be(&out[csumOff], ones_complement_checksum(cbuf.data(), cbuf.size()));
        }

        // --- Send ---
        pcpp::RawPacket* rp = new pcpp::RawPacket();
        timeval tv{}; tv.tv_sec = 0; tv.tv_usec = 0;
        if (!rp->setRawData(out.data(), (int)out.size(), false, tv, pcpp::LINKTYPE_ETHERNET))
        {
            delete rp; if (errOut) *errOut = "Failed to create RawPacket"; return false;
        }

        pcpp::RawPacketVector v; v.pushBack(rp);
        if (m_currentDevice->sendPackets(v) != 1)
        {
            if (errOut) *errOut = "sendPackets failed"; return false;
        }

        // --- Log sent packet into capture lists so UI shows it ---
        try {
            std::vector<std::string> meta;
            SYSTEMTIME st{}; GetLocalTime(&st);
            char timestr[64];
            snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03d",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            meta.push_back(timestr);
            meta.push_back(std::string("Sent"));
            meta.push_back((protocol == 6) ? std::string("TCP")
                : (protocol == 17) ? std::string("UDP") : std::string("OTHER"));

            char srcBuf[20], dstBuf[20];
            auto sip = &out[ipOffset + 12];
            auto dip = &out[ipOffset + 16];
            snprintf(srcBuf, sizeof(srcBuf), "%u.%u.%u.%u", sip[0], sip[1], sip[2], sip[3]);
            snprintf(dstBuf, sizeof(dstBuf), "%u.%u.%u.%u", dip[0], dip[1], dip[2], dip[3]);

            std::string srcPortStr, dstPortStr;
            if (out.size() >= transportOffset + 4)
            {
                srcPortStr = std::to_string(read_u16_be(&out[transportOffset + 0]));
                dstPortStr = std::to_string(read_u16_be(&out[transportOffset + 2]));
            }
            meta.push_back(srcBuf);
            meta.push_back(srcPortStr);
            meta.push_back(dstBuf);
            meta.push_back(dstPortStr);
            meta.push_back(std::to_string(out.size()));
            meta.push_back(std::string("(Matilda)"));

            logOutgoingPacket(out, meta);
        }
        catch (...) {}

        return true;
    }
    catch (const std::exception& ex)
    {
        if (errOut) *errOut = std::string("exception: ") + ex.what(); return false;
    }
    catch (...)
    {
        if (errOut) *errOut = "unknown exception"; return false;
    }
}

// ---------------------------------------------------------------------------
bool CaptureManager::logOutgoingPacket(const std::vector<uint8_t>& frame,
    const std::vector<std::string>& meta)
{
    std::vector<uint8_t> realFrame = frame;
    bool usedPlaceholder = false;
    if (realFrame.empty())
    {
        realFrame.assign(14, 0); // minimal Ethernet placeholder
        usedPlaceholder = true;
    }

    int newIdx = -1;
    try {
        std::lock_guard<std::mutex> lk(m_capturedLock);
        pcpp::RawPacket* rp = new pcpp::RawPacket();
        timeval tv{}; tv.tv_sec = 0; tv.tv_usec = 0;
        // deleteRawDataAtDestructor=false: realFrame is a local copy on our stack;
        // handing ownership would cause a double-free when the vector destructs.
        if (!rp->setRawData(realFrame.data(), (int)realFrame.size(), false, tv,
            pcpp::LINKTYPE_ETHERNET))
        {
            delete rp; return false;
        }
        m_capturedPackets.pushBack(rp);
        newIdx = (int)(m_capturedPackets.size() - 1);
        if (m_capturedMeta.size() <= (size_t)newIdx)
            m_capturedMeta.resize(newIdx + 1);
        m_capturedMeta[newIdx] = meta;
    }
    catch (...) { return false; }

    // Build a summary matching the live-capture format
    std::ostringstream oss;
    for (size_t i = 0; i < meta.size() && i < 9; ++i)
        oss << meta[i] << '\t';
    oss << (usedPlaceholder ? 0 : (int)frame.size()) << '\t';
    oss << "\t---------------------\r\n";

    if (m_uiWindow)
    {
        struct PktMsg { int idx; char* summary; };
        PktMsg* arr = new PktMsg[1];
        arr[0].idx = newIdx;
        arr[0].summary = _strdup(oss.str().c_str());
        PostMessageA((HWND)m_uiWindow, WM_APP + 2, (WPARAM)1, (LPARAM)arr);
    }
    return true;
}

// ---------------------------------------------------------------------------
bool CaptureManager::sendRawPacket(const std::vector<uint8_t>& data)
{
    if (!m_currentDevice || data.empty()) return false;

    pcpp::RawPacket* p = new pcpp::RawPacket();
    timeval tv{}; tv.tv_sec = 0; tv.tv_usec = 0;
    if (!p->setRawData(data.data(), (int)data.size(), false, tv, pcpp::LINKTYPE_ETHERNET))
    {
        delete p; return false;
    }

    pcpp::RawPacketVector tmp;
    tmp.pushBack(p);
    return m_currentDevice->sendPackets(tmp) == 1;
}