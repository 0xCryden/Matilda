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

                    // Store a copy for replay / metadata
                    int newIdx = -1;
                    try {
                        std::lock_guard<std::mutex> lk(m_capturedLock);
                        m_capturedPackets.pushBack(new pcpp::RawPacket(*rawPacket));
                        newIdx = (int)(m_capturedPackets.size() - 1);
                    }
                    catch (...) {}

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
                    if (proto == "TCP")        pid = getPidForTcp(srcIp, dstIp, srcPort, dstPort);
                    else if (proto == "UDP")   pid = getPidForUdp(srcIp, dstIp, srcPort, dstPort);
                    if (pid != 0)              procName = getProcessNameByPid(pid);

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

                    // Store metadata
                    {
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

                        std::lock_guard<std::mutex> lk(m_capturedLock);
                        if (newIdx < 0)
                            m_capturedMeta.push_back(meta);
                        else
                        {
                            if (m_capturedMeta.size() <= (size_t)newIdx)
                                m_capturedMeta.resize(newIdx + 1);
                            m_capturedMeta[newIdx] = meta;
                        }
                    }

                    // Batch UI notifications (max 300 ms or 100 packets between flushes)
                    {
                        std::string summary = out.str();
                        auto now = std::chrono::steady_clock::now();
                        bool doPost = false;
                        int  postCount = 0;

                        {
                            std::lock_guard<std::mutex> lk(m_notifyLock);
                            m_pendingNotifications.emplace_back(newIdx, summary);
                            if (m_lastNotify.time_since_epoch().count() == 0)
                                m_lastNotify = now;
                            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - m_lastNotify).count();
                            if (ms >= 300 || m_pendingNotifications.size() >= 100)
                            {
                                doPost = true;
                                postCount = (int)m_pendingNotifications.size();
                            }
                        }

                        if (doPost)
                        {
                            struct PktMsg { int idx; char* summary; };
                            PktMsg* arr = new PktMsg[postCount];
                            {
                                std::lock_guard<std::mutex> lk(m_notifyLock);
                                for (int i = 0; i < postCount; ++i)
                                {
                                    arr[i].idx = m_pendingNotifications[i].first;
                                    arr[i].summary = _strdup(m_pendingNotifications[i].second.c_str());
                                }
                                m_pendingNotifications.erase(
                                    m_pendingNotifications.begin(),
                                    m_pendingNotifications.begin() + postCount);
                                m_lastNotify = now;
                            }

                            if (m_uiWindow)
                                PostMessageA((HWND)m_uiWindow, WM_APP + 2, (WPARAM)postCount, (LPARAM)arr);
                            else
                            {
                                std::ostringstream agg;
                                for (int i = 0; i < postCount; ++i) agg << arr[i].summary << "\n";
                                if (m_callback) m_callback(agg.str(), -1);
                                for (int i = 0; i < postCount; ++i) free(arr[i].summary);
                                delete[] arr;
                            }
                        }
                        else
                        {
                            if (m_callback) m_callback(std::string(), -1);
                        }
                    }
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

// ---------------------------------------------------------------------------
// Process / PID helpers
// ---------------------------------------------------------------------------
std::string CaptureManager::getProcessNameByPid(DWORD pid)
{
    if (pid == 0) return std::string();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return std::string();
    char  buf[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string name;
    if (QueryFullProcessImageNameA(h, 0, buf, &size))
    {
        const char* p = strrchr(buf, '\\');
        name = p ? (p + 1) : buf;
    }
    CloseHandle(h);
    return name;
}

DWORD CaptureManager::getPidForTcp(const std::string& srcIp, const std::string& dstIp,
    uint16_t srcPort, uint16_t dstPort)
{
    DWORD pid = 0;
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        != ERROR_INSUFFICIENT_BUFFER) return 0;

    auto* table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return 0;

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        in_addr saddr{}, daddr{};
        inet_pton(AF_INET, srcIp.c_str(), &saddr);
        inet_pton(AF_INET, dstIp.c_str(), &daddr);
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            MIB_TCPROW_OWNER_PID& r = table->table[i];
            uint16_t lport = ntohs((u_short)r.dwLocalPort);
            uint16_t rport = ntohs((u_short)r.dwRemotePort);
            if (r.dwLocalAddr == saddr.S_un.S_addr && r.dwRemoteAddr == daddr.S_un.S_addr &&
                lport == srcPort && rport == dstPort)
            {
                pid = r.dwOwningPid; break;
            }
            if (r.dwLocalAddr == daddr.S_un.S_addr && r.dwRemoteAddr == saddr.S_un.S_addr &&
                lport == dstPort && rport == srcPort)
            {
                pid = r.dwOwningPid; break;
            }
        }
    }
    free(table);
    return pid;
}

DWORD CaptureManager::getPidForUdp(const std::string& srcIp, const std::string& dstIp,
    uint16_t srcPort, uint16_t dstPort)
{
    DWORD pid = 0;
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0)
        != ERROR_INSUFFICIENT_BUFFER) return 0;

    auto* table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!table) return 0;

    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        in_addr saddr{}, daddr{};
        inet_pton(AF_INET, srcIp.c_str(), &saddr);
        inet_pton(AF_INET, dstIp.c_str(), &daddr);
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            MIB_UDPROW_OWNER_PID& r = table->table[i];
            uint16_t lport = ntohs((u_short)r.dwLocalPort);
            if ((r.dwLocalAddr == saddr.S_un.S_addr && lport == srcPort) ||
                (r.dwLocalAddr == daddr.S_un.S_addr && lport == dstPort))
            {
                pid = r.dwOwningPid; break;
            }
        }
    }
    free(table);
    return pid;
}

size_t CaptureManager::getCapturedCount() const
{
    std::lock_guard<std::mutex> lk(m_capturedLock);
    return m_capturedPackets.size();
}

bool CaptureManager::setFilter(const std::string& filter)
{
    if (!m_currentDevice) return false;
    return m_currentDevice->setFilter(filter);
}

bool CaptureManager::getCapturedPacketBytes(size_t index, std::vector<uint8_t>& out) const
{
    std::lock_guard<std::mutex> lk(m_capturedLock);
    if (index >= m_capturedPackets.size()) return false;
    pcpp::RawPacket* p = m_capturedPackets.at((int)index);
    if (!p) return false;
    const uint8_t* data = p->getRawData();
    int len = p->getRawDataLen();
    out.assign(data, data + len);
    return true;
}

bool CaptureManager::getCapturedMeta(size_t index, std::vector<std::string>& out) const
{
    std::lock_guard<std::mutex> lk(m_capturedLock);
    if (index >= m_capturedMeta.size()) return false;
    out = m_capturedMeta[index];
    return true;
}