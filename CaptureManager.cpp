#include "CaptureManager.h"
#include <sstream>
#include <chrono>
#include <thread>

// Include WinSock2 first to ensure ntohl/ntohs is available on Windows
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
    auto devices = devList.getPcapLiveDevicesList();
    for (size_t i = 0; i < devices.size(); ++i)
    {
        auto d = devices[i];
        // Prefer human-friendly description if available, otherwise use the device name
        std::string desc = d->getDesc();
        if (!desc.empty())
            out.push_back(desc);
        else
            out.push_back(d->getName());
    }
    return out;
}

bool CaptureManager::openForSend(int deviceIndex)
{
    // If capture is running, m_currentDevice is already open — no need to open separately
    if (m_running && m_currentDevice)
        return true;

    // Close any previously opened send-only device
    if (m_sendOnlyDevice)
    {
        m_sendOnlyDevice->close();
        m_sendOnlyDevice = nullptr;
    }

    auto& devList = pcpp::PcapLiveDeviceList::getInstance();
    auto devices  = devList.getPcapLiveDevicesList();
    if (devices.empty()) return false;

    int idx = deviceIndex;
    if (idx < 0 || idx >= (int)devices.size()) idx = 0;

    pcpp::PcapLiveDevice* dev = devices[idx];
    if (!dev->isOpened())
    {
        if (!dev->open()) return false;
    }
    m_sendOnlyDevice = dev;
    m_currentDevice  = dev; // also expose via m_currentDevice so sendCapturedPacketWithPayload works
    return true;
}

void CaptureManager::closeForSend()
{
    if (m_sendOnlyDevice)
    {
        // Only close if capture isn't also using it
        if (!m_running)
        {
            m_sendOnlyDevice->close();
            if (m_currentDevice == m_sendOnlyDevice)
                m_currentDevice = nullptr;
        }
        m_sendOnlyDevice = nullptr;
    }
}

bool CaptureManager::start(PacketCallback cb, int deviceIndex, void* uiWindow)
{
    if (m_running)
        return false;

    m_callback = std::move(cb);
    m_running = true;
    m_uiWindow = uiWindow;

    // store chosen index via a simple lambda capture
    m_thread = std::thread([this, deviceIndex]() {
        // save index in thread-local by passing to run
        // trick: set a thread-local variable via std::bind isn't needed; just call run with index
        // We'll create an overloaded run that accepts deviceIndex by setting a global in this object temporarily - simpler: call run and have it read a member; add m_deviceIndex member? Simpler: call a lambda that replicates run body with deviceIndex.
        auto& devList = pcpp::PcapLiveDeviceList::getInstance();
        auto devices = devList.getPcapLiveDevicesList();

        if (devices.empty())
        {
            if (m_callback)
                m_callback("No capture devices found\r\n", -1);
            m_running = false;
            return;
        }



        int idx = deviceIndex;
        if (idx < 0 || idx >= (int)devices.size())
            idx = 0;

        pcpp::PcapLiveDevice* dev = devices[idx];
        // remember device for send operations
        m_currentDevice = dev;

        std::string localIp;
        try { localIp = dev->getIPv4Address().toString(); } catch(...) { localIp.clear(); }

        if (!dev->open())
        {
            if (m_callback)
                m_callback("Failed to open device\r\n", -1);
            m_running = false;
            return;
        }

        dev->startCapture(
            [this, localIp](pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice*, void*)
            {
                if (!m_running)
                    return;

                // store a copy of the raw packet for potential replay and metadata
                int newIdx = -1;
                try {
                    std::lock_guard<std::mutex> lk(m_capturedLock);
                    m_capturedPackets.pushBack(new pcpp::RawPacket(*rawPacket));
                    newIdx = (int)(m_capturedPackets.size() - 1);
                } catch(...) {
                    // ignore push failures
                }

                pcpp::Packet packet(rawPacket);

                std::string proto = "OTHER";
                std::string srcIp = "";
                std::string dstIp = "";
                uint16_t srcPort = 0;
                uint16_t dstPort = 0;
                int len = rawPacket->getRawDataLen();

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

                // determine direction: if srcIp equals local device IP then Sent, else Received
                std::string direction = "Recv";
                if (!localIp.empty() && !srcIp.empty() && srcIp == localIp)
                    direction = "Sent";

                // attempt to map packet to owning process (PID -> exe name)
                std::string procName = "";
                DWORD pid = 0;
                if (proto == "TCP")
                {
                    pid = getPidForTcp(srcIp, dstIp, srcPort, dstPort);
                }
                else if (proto == "UDP")
                {
                    pid = getPidForUdp(srcIp, dstIp, srcPort, dstPort);
                }
                if (pid != 0)
                {
                    procName = getProcessNameByPid(pid);
                }

                // build a tab-separated line for ListView columns
                std::ostringstream out;
                // time
                SYSTEMTIME st{};
                GetLocalTime(&st);
                char timestr[64];
                snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                out << timestr << '\t';
                out << direction << '\t';
                out << proto << '\t';
                out << srcIp << '\t' << srcPort << '\t';
                out << dstIp << '\t' << dstPort << '\t';
                out << len << '\t';
                out << procName << '\t';
                out << "---------------------\r\n";

                // store metadata for filtering
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
                    {
                        // fallback: append if index invalid
                        m_capturedMeta.push_back(meta);
                    }
                    else
                    {
                        if (m_capturedMeta.size() <= (size_t)newIdx) m_capturedMeta.resize(newIdx+1);
                        m_capturedMeta[newIdx] = meta;
                    }
                }

                // batch notifications to avoid flooding the UI thread
                {
                    int idx = (int)(m_capturedPackets.size() - 1);
                    std::string summary = out.str();
                    auto now = std::chrono::steady_clock::now();
                    bool doPost = false;
                    int postCount = 0;
                    // add to pending under lock
                    {
                        std::lock_guard<std::mutex> lk(m_notifyLock);
                        m_pendingNotifications.emplace_back(idx, summary);
                        if (m_lastNotify.time_since_epoch().count() == 0)
                            m_lastNotify = now;
                        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastNotify).count();
                        if (ms >= 300 || m_pendingNotifications.size() >= 100)
                        {
                            doPost = true;
                            postCount = (int)m_pendingNotifications.size();
                        }
                    }

                    if (doPost)
                    {
                        // allocate C-friendly array for posting to main window
                        struct PktMsg { int idx; char* summary; };
                        PktMsg* arr = new PktMsg[postCount];
                        {
                            std::lock_guard<std::mutex> lk(m_notifyLock);
                            for (int i = 0; i < postCount; ++i)
                            {
                                arr[i].idx = m_pendingNotifications[i].first;
                                arr[i].summary = _strdup(m_pendingNotifications[i].second.c_str());
                            }
                            // erase first postCount entries
                            m_pendingNotifications.erase(m_pendingNotifications.begin(), m_pendingNotifications.begin() + postCount);
                            m_lastNotify = now;
                        }

                        if (m_uiWindow)
                        {
                            PostMessageA((HWND)m_uiWindow, WM_APP + 2, (WPARAM)postCount, (LPARAM)arr);
                        }
                        else
                        {
                            // fallback: call callback with aggregated text
                            std::ostringstream agg;
                            for (int i = 0; i < postCount; ++i) { agg << arr[i].summary << "\n"; }
                            if (m_callback) m_callback(agg.str(), -1);
                            for (int i = 0; i < postCount; ++i) free(arr[i].summary);
                            delete[] arr;
                        }
                    }
                    else
                    {
                        // no batch ready; optionally log minimal info
                        if (m_callback)
                            m_callback(std::string(""), -1);
                    }
                }
            },
            nullptr);

        while (m_running)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

        dev->stopCapture();
        dev->close();

        m_running = false;
    });
    return true;
}

void CaptureManager::stop()
{
    if (!m_running)
        return;

    m_running = false;
    if (m_thread.joinable())
        m_thread.join();

    // After capture stops, if a send-only device was also set restore pointer
    // (m_currentDevice was set to the capture device inside the thread; after join it's cleared by the thread)
    if (m_sendOnlyDevice)
        m_currentDevice = m_sendOnlyDevice;
}

bool CaptureManager::isRunning() const
{
    return m_running.load();
}

// run() is no longer used; logic moved into the start() thread lambda. Keep run() for backward compat if needed.

// Helper: get process name from PID
std::string CaptureManager::getProcessNameByPid(DWORD pid)
{
    if (pid == 0) return std::string();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return std::string();
    char buf[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string name;
    if (QueryFullProcessImageNameA(h, 0, buf, &size))
    {
        // extract filename
        char* p = strrchr(buf, '\\');
        if (p) name = p + 1; else name = buf;
    }
    CloseHandle(h);
    return name;
}

// Helper: find PID for TCP 5-tuple (IPv4). Tries exact match and reverse match.
DWORD CaptureManager::getPidForTcp(const std::string& srcIp, const std::string& dstIp, uint16_t srcPort, uint16_t dstPort)
{
    DWORD pid = 0;
    PMIB_TCPTABLE_OWNER_PID table = nullptr;
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return 0;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        in_addr saddr{}, daddr{};
        inet_pton(AF_INET, srcIp.c_str(), &saddr);
        inet_pton(AF_INET, dstIp.c_str(), &daddr);
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            MIB_TCPROW_OWNER_PID &r = table->table[i];
            // ports in network byte order in dwLocalPort? In MIB_TCPROW_OWNER_PID, dwLocalPort is in NETWORK order stored in DWORD (big endian).
            uint16_t lport = ntohs((u_short)r.dwLocalPort);
            uint16_t rport = ntohs((u_short)r.dwRemotePort);
            uint32_t laddr = r.dwLocalAddr;
            uint32_t raddr = r.dwRemoteAddr;
            // match exact direction
            if (laddr == saddr.S_un.S_addr && raddr == daddr.S_un.S_addr && lport == srcPort && rport == dstPort)
            {
                pid = r.dwOwningPid; break;
            }
            // reverse direction
            if (laddr == daddr.S_un.S_addr && raddr == saddr.S_un.S_addr && lport == dstPort && rport == srcPort)
            {
                pid = r.dwOwningPid; break;
            }
        }
    }
    free(table);
    return pid;
}

DWORD CaptureManager::getPidForUdp(const std::string& srcIp, const std::string& dstIp, uint16_t srcPort, uint16_t dstPort)
{
    DWORD pid = 0;
    PMIB_UDPTABLE_OWNER_PID table = nullptr;
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;
    table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!table) return 0;
    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        in_addr saddr{}, daddr{};
        inet_pton(AF_INET, srcIp.c_str(), &saddr);
        inet_pton(AF_INET, dstIp.c_str(), &daddr);
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            MIB_UDPROW_OWNER_PID &r = table->table[i];
            uint16_t lport = ntohs((u_short)r.dwLocalPort);
            uint32_t laddr = r.dwLocalAddr;
            if (laddr == saddr.S_un.S_addr && lport == srcPort)
            {
                pid = r.dwOwningPid; break;
            }
            if (laddr == daddr.S_un.S_addr && lport == dstPort)
            {
                pid = r.dwOwningPid; break;
            }
        }
    }
    free(table);
    return pid;
}

void CaptureManager::run()
{
    // deprecated
}

