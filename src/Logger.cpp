#include "Logger.h"
#include <windows.h>
#include <fstream>

Logger::Logger(void* mainWindow, void* outputBox, const std::string& logFile)
    : m_mainWindow(mainWindow), m_outputBox(outputBox), m_logFile(logFile) {}

Logger::~Logger() {}

void Logger::log(const std::string& msg)
{
    // append to file (best-effort)
    std::ofstream f(m_logFile, std::ios::app);
    if (f)
        f << msg;

    // post to UI for display
    postToUi(msg);
}

void Logger::postToUi(const std::string& msg)
{
    // post a copy of the string pointer; receiver must delete
    PostMessageA((HWND)m_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string(msg));
}
