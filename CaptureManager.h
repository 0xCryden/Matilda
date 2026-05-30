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

class CaptureManager {
public:
    using PacketCallback = std::function<void(const std::string&, int)>;

    CaptureManager();
    ~CaptureManager();

    bool start(PacketCallback cb, int deviceIndex = 0, void* uiWindow = nullptr);
    // Open the selected device for sending only (when not capturing).
    // If capture is already running the existing device is used automatically.
    bool openForSend(int deviceIndex);
    void closeForSend();
    void setUiWindow(void* wnd) { m_uiWindow = wnd; }
    std::vector<std::string> getDeviceList() const;
    void stop();
    bool isRunning() const;

    bool sendCapturedPacket(size_t index);
    // send with optional payload override; errOut receives textual error on failure
    bool sendCapturedPacketWithPayload(size_t index,
        const std::vector<uint8_t>& payload,
        const std::string& protoOverride = std::string(),
        const std::string& srcIpOverride = std::string(),
        uint16_t srcPortOverride = 0,
        const std::string& dstIpOverride = std::string(),
        uint16_t dstPortOverride = 0,
        std::string* errOut = nullptr);
    // log an outgoing frame into the captured lists and post UI notification (meta columns must follow capturedMeta convention)
    bool logOutgoingPacket(const std::vector<uint8_t>& frame, const std::vector<std::string>& meta);
    bool sendRawPacket(const std::vector<uint8_t>& data);
    size_t getCapturedCount() const;
    bool setFilter(const std::string& filter);
    bool getCapturedPacketBytes(size_t index, std::vector<uint8_t>& out) const;
    bool getCapturedMeta(size_t index, std::vector<std::string>& out) const;

private:
    std::thread m_thread;
    std::atomic<bool> m_running;
    PacketCallback m_callback;

    pcpp::RawPacketVector m_capturedPackets;
    std::vector<std::vector<std::string>> m_capturedMeta;
    mutable std::mutex m_capturedLock;

    pcpp::PcapLiveDevice* m_currentDevice = nullptr;
    pcpp::PcapLiveDevice* m_sendOnlyDevice = nullptr; // opened by openForSend(), not for capture
    void* m_uiWindow = nullptr;

    std::vector<std::pair<int, std::string>> m_pendingNotifications;
    std::chrono::steady_clock::time_point m_lastNotify;
    std::mutex m_notifyLock;

    // private helpers
    static std::string getProcessNameByPid(DWORD pid);
    static DWORD getPidForTcp(const std::string& srcIp, const std::string& dstIp, uint16_t srcPort, uint16_t dstPort);
    static DWORD getPidForUdp(const std::string& srcIp, const std::string& dstIp, uint16_t srcPort, uint16_t dstPort);

    void run();
};


