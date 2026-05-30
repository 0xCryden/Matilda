#pragma once

#include <string>
#include <cstdint>
#include "../Platform.h"

// Helper class to map network tuples to PIDs and retrieve process names.
class ProcessMapper {
public:
    static std::string getProcessNameByPid(DWORD pid);
    static DWORD getPidForTcp(const std::string& srcIp, const std::string& dstIp,
        uint16_t srcPort, uint16_t dstPort);
    static DWORD getPidForUdp(const std::string& srcIp, const std::string& dstIp,
        uint16_t srcPort, uint16_t dstPort);
};
