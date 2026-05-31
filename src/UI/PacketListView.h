#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <functional>

// PacketListView: manages packet list control and WM_APP+2 insertion logic.
// Role: create/manage listview control, SetupListViewColumns, insert/filter packets,
//       handle WM_APP+2 batch notification messages.
class PacketListView
{
public:
    using SelectionCallback = std::function<void(int packetIndex, const std::vector<uint8_t>&)>;

    explicit PacketListView(HWND parentHwnd);
    ~PacketListView();

    // Create and initialize the ListView control.
    bool create();

    // Set up list view columns (Time, Direction, Proto, SrcIP, SrcPort, DstIP, DstPort, Len, Process).
    void setupColumns();

    // Handle WM_APP+2 batch insertion message from NotificationDispatcher.
    // wParam: count of messages, lParam: pointer to PktMsg array
    void handleBatchInsert(int count, LPARAM lParam);

    // Insert a single packet row (called by handleBatchInsert for each packet).
    void insertPacketRow(int packetIndex, const std::string& summary);

    // Clear all rows from the list view.
    void clear();

    // Get the control's HWND.
    HWND getHWnd() const { return m_hWnd; }

    // Set filter by application process name; empty string = show all.
    void setApplicationFilter(const std::string& appName);

    // Rebuild list view based on current filter and full packet list.
    void rebuildFromPacketStore(
        size_t totalPackets,
        std::function<bool(size_t, std::vector<std::string>&)> getMetaFunc);

private:
    HWND m_hWnd;
    HWND m_parentHwnd;
    std::string m_currentAppFilter;

    // Parse tab-separated summary into column strings.
    static std::vector<std::string> parseSummary(const std::string& summary);

    // Check if packet should be shown based on current filter.
    bool shouldShowPacket(const std::vector<std::string>& cols) const;
};
