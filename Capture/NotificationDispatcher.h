#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>

// Callback signature: (aggregatedSummary, count) or use WM message when uiWindow set
using NotificationCallback = std::function<void(const std::string&, int)>;

class NotificationDispatcher {
public:
    NotificationDispatcher();
    ~NotificationDispatcher();

    // Enqueue a single packet summary (index + summary text).
    void enqueue(int idx, const std::string& summary);

    // Set callback; dispatcher will call periodically or when flush conditions met.
    void setCallback(NotificationCallback cb);

    // Force flush pending notifications (synchronously call callback)
    void flush(bool postToUi = false);

private:
    std::mutex m_lock;
    std::vector<std::pair<int, std::string>> m_pending;
    std::chrono::steady_clock::time_point m_lastNotify;
    NotificationCallback m_callback;
};
