#include "CaptureManager.h"
#include <sstream>
#include <chrono>
#include <thread>

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include "PcapLiveDeviceList.h"
#include <windows.h>
#include <psapi.h>
#include "Capture/ProcessMapper.h"
#include "PcapLiveDevice.h"
#include "Packet.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IPv4Layer.h"


CaptureManager::CaptureManager()
    : m_running(false)
{
}

CaptureManager::~CaptureManager()
{
    stop();
}

std::vector<std::string> CaptureManager::getDeviceList() const
{
    std::vector<std::string> out;
    auto& devList = pcpp::PcapLiveDeviceList::getInstance();
    auto  devices = devList.getPcapLiveDevicesList();
    for (size_t i = 0; i < devices.size(); ++i)
    {
        auto        d = devices[i];
        std::string desc = d->getDesc();
        out.push_back(desc.empty() ? d->getName() : desc);
    }
    return out;
}

bool CaptureManager::start(PacketCallback cb, int deviceIndex, void* uiWindow)
{
    if (m_running)
        return false;

    m_callback = std::move(cb);
    m_running = true;
    m_uiWindow = uiWindow;
    // Wire notification dispatcher to UI/callback
    m_notifier.setCallback(m_callback);
    if (m_uiWindow) m_notifier.setUiWindow((HWND)m_uiWindow);

    m_thread = std::thread([this, deviceIndex]()
        {
            auto& devList = pcpp::PcapLiveDeviceList::getInstance();
            auto  devices = devList.getPcapLiveDevicesList();

            if (devices.empty())
            {
                if (m_callback) m_callback("No capture devices found\r\n", -1);
                m_running = false;
                return;
            }

            int idx = deviceIndex;
            if (idx < 0 || idx >= (int)devices.size()) idx = 0;

            pcpp::PcapLiveDevice* dev = devices[idx];
            m_currentDevice = dev;

            std::string localIp;
            try { localIp = dev->getIPv4Address().toString(); }
            catch (...) { localIp.clear(); }

            if (!dev->open())
            {
                if (m_callback) m_callback("Failed to open device\r\n", -1);
                m_running = false;
                m_currentDevice = nullptr;
                return;
            }

            dev->startCapture(
                [this, localIp](pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice*, void*)
                {
                    if (!m_running) return;

                    // Feed raw bytes to the connection tracker before anything else
                    m_connTracker.observe(rawPacket->getRawData(), rawPacket->getRawDataLen());

                    pcpp::Packet packet(rawPacket);

                    std::string proto = "OTHER";
                    std::string srcIp = "";
                    std::string dstIp = "";
                    uint16_t    srcPort = 0;
                    uint16_t    dstPort = 0;
                    int         len = rawPacket->getRawDataLen();

                    auto ip = packet.getLayerOfType<pcpp::IPv4Layer>();
                    if (ip)
                    {
                        srcIp = ip->getSrcIPAddress().toString();
                        dstIp = ip->getDstIPAddress().toString();
                    }

                    auto tcp = packet.getLayerOfType<pcpp::TcpLayer>();
                    if (tcp)
                    {
                        proto = "TCP";
                        auto h = tcp->getTcpHeader();
                        srcPort = ntohs(h->portSrc);
                        dstPort = ntohs(h->portDst);
                    }
                    else
                    {
                        auto udp = packet.getLayerOfType<pcpp::UdpLayer>();
                        if (udp)
                        {
                            proto = "UDP";
                            auto uh = udp->getUdpHeader();
                            srcPort = ntohs(uh->portSrc);
                            dstPort = ntohs(uh->portDst);
                        }
                    }

                    std::string direction = (!localIp.empty() && !srcIp.empty() && srcIp == localIp)
                        ? "Sent" : "Recv";

                    // Map packet to owning process
                    std::string procName;
                    DWORD pid = 0;
                    if (proto == "TCP")        pid = ProcessMapper::getPidForTcp(srcIp, dstIp, srcPort, dstPort);
                    else if (proto == "UDP")   pid = ProcessMapper::getPidForUdp(srcIp, dstIp, srcPort, dstPort);
                    if (pid != 0)              procName = ProcessMapper::getProcessNameByPid(pid);

                    // Build tab-separated summary for ListView
                    std::ostringstream out;
                    SYSTEMTIME st{};
                    GetLocalTime(&st);
                    char timestr[64];
                    snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03d",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                    out << timestr << '\t'
                        << direction << '\t'
                        << proto << '\t'
                        << srcIp << '\t' << srcPort << '\t'
                        << dstIp << '\t' << dstPort << '\t'
                        << len << '\t'
                        << procName << '\t'
                        << "---------------------\r\n";

                    // Store metadata and packet into PacketStore
                    int newIdx = -1;
                    try {
                        std::vector<std::string> meta;
                        meta.push_back(timestr);
                        meta.push_back(direction);
                        meta.push_back(proto);
                        meta.push_back(srcIp);
                        meta.push_back(std::to_string(srcPort));
                        meta.push_back(dstIp);
                        meta.push_back(std::to_string(dstPort));
                        meta.push_back(std::to_string(len));
                        meta.push_back(procName);

                        pcpp::RawPacket* copy = new pcpp::RawPacket(*rawPacket);
                        m_packetStore.appendPacket(copy, meta);
                        size_t cnt = m_packetStore.getCount();
                        if (cnt > 0) newIdx = (int)(cnt - 1);
                    }
                    catch (...) { }

                    // Enqueue notification; if not flushed immediately, call callback with empty string like before
                    std::string summary = out.str();
                    bool flushed = m_notifier.enqueue(newIdx, summary);
                    if (!flushed && m_callback) m_callback(std::string(), -1);
                },
                nullptr);

            while (m_running)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            dev->stopCapture();
            dev->close();
            m_currentDevice = nullptr;
            m_running = false;
        });

    return true;
}

void CaptureManager::stop()
{
    if (!m_running) return;
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
}

bool CaptureManager::isRunning() const
{
    return m_running.load();
}

void CaptureManager::run()
{
    // Deprecated — logic lives in the start() thread lambda.
}

// Process mapping delegated to Capture/ProcessMapper

size_t CaptureManager::getCapturedCount() const
{
    return m_packetStore.getCount();
}

bool CaptureManager::setFilter(const std::string& filter)
{
    if (!m_currentDevice) return false;
    return m_currentDevice->setFilter(filter);
}

bool CaptureManager::getCapturedPacketBytes(size_t index, std::vector<uint8_t>& out) const
{
    return m_packetStore.getPacketBytes(index, out);
}

bool CaptureManager::getCapturedMeta(size_t index, std::vector<std::string>& out) const
{
    return m_packetStore.getMeta(index, out);
}