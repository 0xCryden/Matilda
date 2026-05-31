#include "DeviceEnumerator.h"
#include "PcapLiveDeviceList.h"

std::vector<std::string> DeviceEnumerator::getDeviceList()
{
    std::vector<std::string> out;
    auto& devList = pcpp::PcapLiveDeviceList::getInstance();
    auto devices = devList.getPcapLiveDevicesList();
    for (size_t i = 0; i < devices.size(); ++i) {
        auto d = devices[i];
        std::string desc = d->getDesc();
        out.push_back(desc.empty() ? d->getName() : desc);
    }
    return out;
}
