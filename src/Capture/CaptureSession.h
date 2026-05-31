#pragma once

#include <functional>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <memory>

namespace pcpp {
    class RawPacket;
}

class CaptureDevice;
class PacketStore;
class NotificationDispatcher;
class ConnectionTracker;

// CaptureSession: manages capture thread lifecycle and coordinates packet storage/notifications.
// Role: manage capture thread, select device, start/stop loop; forwards packets to PacketStore, 
//       ConnectionTracker, NotificationDispatcher.
class CaptureSession
{
public:
    using PacketCallback = std::function<void(const std::string&, int)>;

    CaptureSession(
        PacketStore* packetStore,
        NotificationDispatcher* notifier,
        ConnectionTracker* connTracker);
    ~CaptureSession();

    // Start capture on the device at the given index.
    // cb is called from the capture thread with log text and packet index.
    // uiWindow receives WM_APP+2 batch notifications (can be nullptr).
    bool start(PacketCallback cb, int deviceIndex = 0, void* uiWindow = nullptr);

    // Stop capture and join thread.
    void stop();

    // Is capture running?
    bool isRunning() const;

    // Get the IP address of the current capture device.
    std::string getLocalIpAddress() const;

    // Get current device (for debugging/testing).
    CaptureDevice* getCurrentDevice() const;

private:
    PacketStore* m_packetStore;
    NotificationDispatcher* m_notifier;
    ConnectionTracker* m_connTracker;

    std::unique_ptr<CaptureDevice> m_device;
    std::thread m_thread;
    std::atomic<bool> m_running;
    PacketCallback m_callback;
    void* m_uiWindow;
};
