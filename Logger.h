#pragma once

#include <string>

class Logger {
public:
    Logger(void* mainWindow, void* outputBox, const std::string& logFile = "Matilda.log");
    ~Logger();

    void log(const std::string& msg);

private:
    void* m_mainWindow;
    void* m_outputBox;
    std::string m_logFile;

    void postToUi(const std::string& msg);
};

