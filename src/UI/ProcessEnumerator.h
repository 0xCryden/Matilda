#pragma once

#include <windows.h>
#include <string>
#include <vector>

// ProcessEnumerator: encapsulates process enumeration for combo box population.
// Role: PopulateProcessCombo / enumerate running processes (previous PopulateProcessCombo code).
class ProcessEnumerator
{
public:
    // Populate a combo box with running processes.
    // Returns count of processes added.
    static int populateCombo(HWND hCombo);

    // Get list of process names (simple names, not paths).
    static std::vector<std::string> getRunningProcesses();
};
