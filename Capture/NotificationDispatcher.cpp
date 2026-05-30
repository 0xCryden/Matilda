#include "Capture/NotificationDispatcher.h"
#include <sstream>
#include <cstring>

struct PktMsg { int idx; char* summary; };

NotificationDispatcher::NotificationDispatcher()
{
}

NotificationDispatcher::~NotificationDispatcher()
{
}

bool NotificationDispatcher::enqueue(int idx, const std::string& summary)
{
    std::lock_guard<std::mutex> lk(m_lock);
    m_pending.emplace_back(idx, summary);
    if (m_lastNotify.time_since_epoch().count() == 0)
        m_lastNotify = std::chrono::steady_clock::now();

    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastNotify).count();
    if (ms >= 300 || m_pending.size() >= 100)
    {
        std::vector<std::pair<int, std::string>> toPost;
        toPost.swap(m_pending);
        m_lastNotify = now;

        if (m_uiWindow)
        {
            int postCount = (int)toPost.size();
            PktMsg* arr = new PktMsg[postCount];
            for (int i = 0; i < postCount; ++i)
            {
                arr[i].idx = toPost[i].first;
                arr[i].summary = _strdup(toPost[i].second.c_str());
            }
            PostMessageA(m_uiWindow, WM_APP + 2, (WPARAM)postCount, (LPARAM)arr);
        }
        else if (m_callback)
        {
            std::ostringstream agg;
            for (auto &p : toPost) agg << p.second << "\n";
            m_callback(agg.str(), (int)toPost.size());
        }
        return true;
    }
    return false;
}

void NotificationDispatcher::setCallback(NotificationCallback cb)
{
    std::lock_guard<std::mutex> lk(m_lock);
    m_callback = cb;
}

void NotificationDispatcher::setUiWindow(HWND uiWindow)
{
    std::lock_guard<std::mutex> lk(m_lock);
    m_uiWindow = uiWindow;
}

void NotificationDispatcher::flush()
{
    std::vector<std::pair<int, std::string>> toPost;
    {
        std::lock_guard<std::mutex> lk(m_lock);
        toPost.swap(m_pending);
        m_lastNotify = std::chrono::steady_clock::now();
    }
    if (toPost.empty()) return;

    if (m_uiWindow)
    {
        int postCount = (int)toPost.size();
        PktMsg* arr = new PktMsg[postCount];
        for (int i = 0; i < postCount; ++i)
        {
            arr[i].idx = toPost[i].first;
            arr[i].summary = _strdup(toPost[i].second.c_str());
        }
        PostMessageA(m_uiWindow, WM_APP + 2, (WPARAM)postCount, (LPARAM)arr);
    }
    else if (m_callback)
    {
        std::ostringstream agg;
        for (auto &p : toPost) agg << p.second << "\n";
        m_callback(agg.str(), (int)toPost.size());
    }
}
