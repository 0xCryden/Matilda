#include <WinSock2.h>
#include <Ws2tcpip.h>
#include "CaptureManager.h"
#include "Net/PacketRewriter.h"
#include <ctime>
#include <sstream>

// ---------------------------------------------------------------------------
bool CaptureManager::sendCapturedPacket(size_t index)
{
    if (!m_currentDevice) return false;

    pcpp::RawPacket* rp = m_packetStore.clonePacket(index);
    if (!rp) return false;

    pcpp::RawPacketVector tmp;
    tmp.pushBack(rp);
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
    // Delegate to PacketRewriter to centralize packet rewriting and sending.
    if (!m_running || !m_currentDevice)
    {
        if (errOut) *errOut = "Capture must be running to send packets";
        return false;
    }
    if (index >= m_packetStore.getCount())
    {
        if (errOut) *errOut = "Invalid packet index";
        return false;
    }

    std::vector<uint8_t> data;
    if (!m_packetStore.getPacketBytes(index, data))
    {
        if (errOut) *errOut = "Original packet missing";
        return false;
    }

    return PacketRewriter::sendWithOverrides(
        data,
        payload,
        protoOverride,
        srcIpOverride,
        srcPortOverride,
        dstIpOverride,
        dstPortOverride,
        &m_connTracker,
        [this](const std::vector<uint8_t>& bytes) { return this->sendRawPacket(bytes); },
        errOut);
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
        m_packetStore.appendOutgoing(realFrame, meta);
        size_t cnt = m_packetStore.getCount();
        if (cnt > 0) newIdx = (int)(cnt - 1);
    }
    catch (...) { return false; }

    // Build a summary matching the live-capture format
    std::ostringstream oss;
    for (size_t i = 0; i < meta.size() && i < 9; ++i)
        oss << meta[i] << '\t';
    oss << (usedPlaceholder ? 0 : (int)frame.size()) << '\t';
    oss << "\t---------------------\r\n";

    // If UI window is present, post immediately (keep original behavior for outgoing)
    if (m_uiWindow)
    {
        struct PktMsg { int idx; char* summary; };
        PktMsg* arr = new PktMsg[1];
        arr[0].idx = newIdx;
        arr[0].summary = _strdup(oss.str().c_str());
        PostMessageA((HWND)m_uiWindow, WM_APP + 2, (WPARAM)1, (LPARAM)arr);
        return true;
    }

    // Otherwise, enqueue into notifier (may flush immediately) and mimic prior callback wake
    bool flushed = m_notifier.enqueue(newIdx, oss.str());
    if (!flushed && m_callback) m_callback(std::string(), -1);
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