#pragma once

#include <cstdint>
#include <functional>

namespace pcpp {
    class PcapLiveDevice;
    class RawPacket;
}

// CaptureDevice: wraps a single pcpp::PcapLiveDevice for capture lifecycle.
// Role: open/close device, start/stop capture callback (no threading).
// Callback: receives RawPacket* on each captured packet.
class CaptureDevice
{
public:
    using CaptureCallback = std::function<void(pcpp::RawPacket*, pcpp::PcapLiveDevice*, void*)>;

    explicit CaptureDevice(pcpp::PcapLiveDevice* device);
    ~CaptureDevice();

    // Open the device for capture. Returns true on success.
    bool open();

    // Close the device. Stops capture if running.
    void close();

    // Is the device currently open?
    bool isOpen() const;

    // Start packet capture with the given callback.
    // Callback fires on each packet received.
    void startCapture(CaptureCallback callback, void* userData = nullptr);

    // Stop packet capture. Blocks until capture thread stops.
    void stopCapture();

    // Get the underlying device pointer.
    pcpp::PcapLiveDevice* getDevice() const;

private:
    pcpp::PcapLiveDevice* m_device;
    bool m_isOpen;
};
