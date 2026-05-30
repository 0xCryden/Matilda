#include "ProcessMapper.h"
#include "../Platform.h"
#pragma comment(lib, "iphlpapi.lib")

#include <cstring>

std::string ProcessMapper::getProcessNameByPid(DWORD pid)
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

DWORD ProcessMapper::getPidForTcp(const std::string& srcIp, const std::string& dstIp,
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

DWORD ProcessMapper::getPidForUdp(const std::string& srcIp, const std::string& dstIp,
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
