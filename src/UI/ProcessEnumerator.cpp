#include "ProcessEnumerator.h"
#include <psapi.h>
#include <unordered_set>
#include <cstring>

int ProcessEnumerator::populateCombo(HWND hCombo)
{
    if (!hCombo) return 0;

    std::unordered_set<std::string> seen;
    int count = 0;

    DWORD aProcesses[1024]{};
    DWORD cbNeeded = 0;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return 0;

    DWORD procCount = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < procCount; ++i) {
        DWORD pid = aProcesses[i];
        if (!pid) continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;

        char buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameA(h, 0, buf, &sz)) {
            const char* p = strrchr(buf, '\\');
            const char* name = p ? p + 1 : buf;
            if (name && name[0]) {
                std::string sname = name;
                if (sname != "All Applications" && !seen.count(sname)) {
                    seen.insert(sname);
                    if (SendMessageA(hCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)sname.c_str()) == CB_ERR) {
                        SendMessageA(hCombo, CB_ADDSTRING, 0, (LPARAM)sname.c_str());
                        count++;
                    }
                }
            }
        }

        CloseHandle(h);
    }

    return count;
}

std::vector<std::string> ProcessEnumerator::getRunningProcesses()
{
    std::vector<std::string> processes;
    std::unordered_set<std::string> seen;

    DWORD aProcesses[1024]{};
    DWORD cbNeeded = 0;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return processes;

    DWORD procCount = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < procCount; ++i) {
        DWORD pid = aProcesses[i];
        if (!pid) continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;

        char buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameA(h, 0, buf, &sz)) {
            const char* p = strrchr(buf, '\\');
            const char* name = p ? p + 1 : buf;
            if (name && name[0]) {
                std::string sname = name;
                if (sname != "All Applications" && !seen.count(sname)) {
                    seen.insert(sname);
                    processes.push_back(sname);
                }
            }
        }

        CloseHandle(h);
    }

    return processes;
}
