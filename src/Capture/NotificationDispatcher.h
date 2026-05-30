#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <functional>
#include <windows.h>

// Callback signature: (aggregatedSummary, count)
using NotificationCallback = std::function<void(const std::string&, int)>;

class NotificationDispatcher {
public:
    NotificationDispatcher();
    ~NotificationDispatcher();

    // Enqueue a single packet summary (index + summary text).
    // Returns true if a flush occurred immediately
    bool enqueue(int idx, const std::string& summary);

    // Set callback; dispatcher will call periodically or when flush conditions met.
    void setCallback(NotificationCallback cb);

    // If uiWindow is provided, dispatcher will PostMessageA(WM_APP+2, count, arr) like original behavior.
    void setUiWindow(HWND uiWindow);

    // Force flush pending notifications (synchronously call callback or post to UI)
    void flush();

private:
    std::mutex m_lock;
    std::vector<std::pair<int, std::string>> m_pending;
    std::chrono::steady_clock::time_point m_lastNotify;
    NotificationCallback m_callback;
    HWND m_uiWindow = nullptr;
};
