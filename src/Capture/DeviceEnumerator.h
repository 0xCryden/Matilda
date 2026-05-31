#pragma once

#include <vector>
#include <string>

// DeviceEnumerator: encapsulates device enumeration logic.
// Role: enumerate PcapLiveDevice list (getDeviceList).
class DeviceEnumerator
{
public:
    // Get list of available capture devices (descriptions or names).
    static std::vector<std::string> getDeviceList();
};
