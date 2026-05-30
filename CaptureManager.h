#pragma once

#include <atomic>
#include <thread>
#include <functional>
#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <mutex>

#include "PcapLiveDevice.h"
#include "RawPacket.h"
#include "ConnectionTracker.h"
#include "Capture/PacketStore.h"
#include "Capture/NotificationDispatcher.h"

class CaptureManager {
public:
    using PacketCallback = std::function<void(const std::string&, int)>;

    CaptureManager();
    ~CaptureManager();

    // Start live capture on the given device index.
    // cb is called (from the capture thread) with log text and packet index.
    // uiWindow receives WM_APP+2 batch notifications.
    bool start(PacketCallback cb, int deviceIndex = 0, void* uiWindow = nullptr);

    void setUiWindow(void* wnd) { m_uiWindow = wnd; }
    std::vector<std::string> getDeviceList() const;
    void stop();
    bool isRunning() const;

    // Send the captured packet at index unchanged.
    bool sendCapturedPacket(size_t index);

    // Send a captured packet, optionally replacing payload / overriding fields.
    // Requires capture to be running (device must be open).
    // errOut receives a textual description of any failure.
    bool sendCapturedPacketWithPayload(size_t index,
        const std::vector<uint8_t>& payload,
        const std::string& protoOverride = std::string(),
        const std::string& srcIpOverride = std::string(),
        uint16_t           srcPortOverride = 0,
        const std::string& dstIpOverride = std::string(),
        uint16_t           dstPortOverride = 0,
        std::string* errOut = nullptr);

    // Log an outgoing frame into the capture lists and post a UI notification.
    // meta columns must follow the capturedMeta convention (same order as live capture).
    bool logOutgoingPacket(const std::vector<uint8_t>& frame,
        const std::vector<std::string>& meta);

    bool   sendRawPacket(const std::vector<uint8_t>& data);
    size_t getCapturedCount() const;
    bool   setFilter(const std::string& filter);
    bool   getCapturedPacketBytes(size_t index, std::vector<uint8_t>& out) const;
    bool   getCapturedMeta(size_t index, std::vector<std::string>& out) const;

private:
    std::thread        m_thread;
    std::atomic<bool>  m_running;
    PacketCallback     m_callback;

    // Thread-safe storage for captured packets and metadata
    PacketStore                       m_packetStore;

    // Notification batching / dispatch (posts WM_APP+2 or calls callback)
    NotificationDispatcher            m_notifier;

    // The device in use during an active capture session.
    // Null when capture is not running - sending is only permitted while capturing.
    pcpp::PcapLiveDevice* m_currentDevice = nullptr;

    void* m_uiWindow = nullptr;

    // Per-connection TCP sequence / acknowledgement tracking
    ConnectionTracker m_connTracker;

    // Private helpers

    // Private helpers
    static std::string  getProcessNameByPid(DWORD pid);
    static DWORD        getPidForTcp(const std::string& srcIp, const std::string& dstIp,
        uint16_t srcPort, uint16_t dstPort);
    static DWORD        getPidForUdp(const std::string& srcIp, const std::string& dstIp,
        uint16_t srcPort, uint16_t dstPort);

    void run(); // deprecated � kept for link compatibility
};