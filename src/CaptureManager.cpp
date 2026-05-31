#include "CaptureManager.h"
#include "Capture/DeviceEnumerator.h"
#include "Capture/CaptureSession.h"
#include "Capture/CaptureDevice.h"
#include "Net/PacketRewriter.h"
#include <sstream>
#include <vector>
#include <WinSock2.h>
#include <windows.h>
#include "RawPacket.h"

CaptureManager::CaptureManager()
    : m_currentDevice(nullptr)
    , m_uiWindow(nullptr)
{
}

CaptureManager::~CaptureManager()
{
    stop();
}

std::vector<std::string> CaptureManager::getDeviceList() const
{
    return DeviceEnumerator::getDeviceList();
}

bool CaptureManager::start(PacketCallback cb, int deviceIndex, void* uiWindow)
{
    if (!m_session) {
        m_session = std::make_unique<CaptureSession>(&m_packetStore, &m_notifier, &m_connTracker);
    }

    return m_session->start(std::move(cb), deviceIndex, uiWindow);
}

void CaptureManager::stop()
{
    if (m_session) {
        m_session->stop();
    }
}

bool CaptureManager::isRunning() const
{
    return m_session && m_session->isRunning();
}

bool CaptureManager::sendCapturedPacket(size_t index)
{
    if (!m_packetStore.getCount() || index >= m_packetStore.getCount())
        return false;

    std::vector<uint8_t> bytes;
    if (!m_packetStore.getPacketBytes(index, bytes))
        return false;

    return sendRawPacket(bytes);
}

bool CaptureManager::sendCapturedPacketWithPayload(size_t index,
    const std::vector<uint8_t>& payload,
    const std::string& protoOverride,
    const std::string& srcIpOverride,
    uint16_t srcPortOverride,
    const std::string& dstIpOverride,
    uint16_t dstPortOverride,
    std::string* errOut)
{
    if (!m_packetStore.getCount() || index >= m_packetStore.getCount()) {
        if (errOut) *errOut = "Invalid packet index";
        return false;
    }

    std::vector<uint8_t> origFrame;
    if (!m_packetStore.getPacketBytes(index, origFrame)) {
        if (errOut) *errOut = "Failed to retrieve packet";
        return false;
    }

    return PacketRewriter::sendWithOverrides(
        origFrame,
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

bool CaptureManager::logOutgoingPacket(const std::vector<uint8_t>& frame,
    const std::vector<std::string>& meta)
{
    std::vector<uint8_t> realFrame = frame;
    bool usedPlaceholder = false;
    if (realFrame.empty()) {
        realFrame.assign(14, 0); // minimal Ethernet placeholder
        usedPlaceholder = true;
    }

    int newIdx = -1;
    try {
        m_packetStore.appendOutgoing(realFrame, meta);
        size_t cnt = m_packetStore.getCount();
        if (cnt > 0) newIdx = (int)(cnt - 1);
    }
    catch (...) { 
        return false; 
    }

    // Build a summary matching the live-capture format
    std::ostringstream oss;
    for (size_t i = 0; i < meta.size() && i < 9; ++i)
        oss << meta[i] << '\t';
    oss << (usedPlaceholder ? 0 : (int)frame.size()) << '\t';
    oss << "\t---------------------\r\n";

    // If UI window is present, post immediately (keep original behavior for outgoing)
    if (m_uiWindow) {
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

bool CaptureManager::sendRawPacket(const std::vector<uint8_t>& data)
{
    if (!isRunning() || !m_session || data.empty())
        return false;

    auto dev = m_session->getCurrentDevice();
    if (!dev || !dev->getDevice())
        return false;

    try {
        pcpp::RawPacket* p = new pcpp::RawPacket();
        timeval tv{}; 
        tv.tv_sec = 0; 
        tv.tv_usec = 0;
        if (!p->setRawData(data.data(), (int)data.size(), false, tv, pcpp::LINKTYPE_ETHERNET)) {
            delete p; 
            return false;
        }

        pcpp::RawPacketVector tmp;
        tmp.pushBack(p);
        return dev->getDevice()->sendPackets(tmp) == 1;
    }
    catch (...) {
        return false;
    }
}

size_t CaptureManager::getCapturedCount() const
{
    return m_packetStore.getCount();
}

bool CaptureManager::setFilter(const std::string& filter)
{
    // Filter support: would be implemented on CaptureDevice if needed
    return true;
}

bool CaptureManager::getCapturedPacketBytes(size_t index, std::vector<uint8_t>& out) const
{
    return m_packetStore.getPacketBytes(index, out);
}

bool CaptureManager::getCapturedMeta(size_t index, std::vector<std::string>& out) const
{
    return m_packetStore.getMeta(index, out);
}
