#include "PacketListView.h"
#include <sstream>
#include <algorithm>
#include <commctrl.h>

PacketListView::PacketListView(HWND parentHwnd)
    : m_hWnd(nullptr)
    , m_parentHwnd(parentHwnd)
    , m_currentAppFilter("")
{
}

PacketListView::~PacketListView()
{
    if (m_hWnd) {
        DestroyWindow(m_hWnd);
    }
}

bool PacketListView::create()
{
    if (!m_parentHwnd) return false;

    // Create ListView control
    m_hWnd = CreateWindowExA(0, WC_LISTVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        0, 0, 100, 100, // Will be positioned by parent
        m_parentHwnd,
        nullptr,
        GetModuleHandleA(nullptr),
        nullptr);

    if (!m_hWnd) return false;

    // Enable full row selection
    SendMessageA(m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES));

    setupColumns();
    return true;
}

void PacketListView::setupColumns()
{
    if (!m_hWnd) return;

    LVCOLUMNA col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    const char* colNames[] = {
        "Pkt#", "Time", "Direction", "Protocol",
        "Src IP", "Src Port", "Dst IP", "Dst Port", "Length", "Process"
    };
    const int colWidths[] = { 50, 100, 70, 60, 120, 70, 120, 70, 60, 120 };

    for (int i = 0; i < 10; ++i) {
        col.pszText = const_cast<char*>(colNames[i]);
        col.cx = colWidths[i];
        SendMessageA(m_hWnd, LVM_INSERTCOLUMNA, i, (LPARAM)&col);
    }
}

std::vector<std::string> PacketListView::parseSummary(const std::string& summary)
{
    std::vector<std::string> cols;
    std::string s = summary;
    size_t pos = 0;

    while (true) {
        size_t tab = s.find('\t', pos);
        if (tab == std::string::npos) {
            cols.push_back(s.substr(pos));
            break;
        }
        cols.push_back(s.substr(pos, tab - pos));
        pos = tab + 1;
        if (pos >= s.size()) break;
    }

    return cols;
}

bool PacketListView::shouldShowPacket(const std::vector<std::string>& cols) const
{
    if (m_currentAppFilter.empty() || m_currentAppFilter == "All Applications") {
        return true;
    }

    if (cols.size() <= 8) return true;

    std::string proc = cols[8];
    // Strip trailing whitespace (newlines, etc)
    while (!proc.empty() && (proc.back() == '\n' || proc.back() == '\r')) {
        proc.pop_back();
    }

    return proc == m_currentAppFilter;
}

void PacketListView::insertPacketRow(int packetIndex, const std::string& summary)
{
    if (!m_hWnd) return;

    std::vector<std::string> cols = parseSummary(summary);

    if (!shouldShowPacket(cols)) return;

    int itemIndex = (int)SendMessageA(m_hWnd, LVM_GETITEMCOUNT, 0, 0);
    LVITEMA it{};
    it.mask = LVIF_TEXT | LVIF_PARAM;
    it.iItem = itemIndex;
    it.lParam = (LPARAM)packetIndex;

    char idbuf[32];
    snprintf(idbuf, sizeof(idbuf), "%d", packetIndex);
    it.pszText = idbuf;

    SendMessageA(m_hWnd, LVM_INSERTITEMA, 0, (LPARAM)&it);

    // Insert column data
    for (int c = 0; c < (int)cols.size() && c < 9; ++c) {
        LVITEMA sub{};
        sub.mask = LVIF_TEXT;
        sub.iItem = itemIndex;
        sub.iSubItem = c + 1;
        sub.pszText = const_cast<char*>(cols[c].c_str());
        SendMessageA(m_hWnd, LVM_SETITEMA, 0, (LPARAM)&sub);
    }
}

void PacketListView::handleBatchInsert(int count, LPARAM lParam)
{
    if (!m_hWnd || count <= 0 || !lParam) return;

    struct PktMsg { int idx; char* summary; };
    PktMsg* arr = (PktMsg*)lParam;

    for (int i = 0; i < count; ++i) {
        if (arr[i].summary && arr[i].summary[0]) {
            insertPacketRow(arr[i].idx, std::string(arr[i].summary));
            free(arr[i].summary);
        }
    }

    free(arr);
}

void PacketListView::clear()
{
    if (!m_hWnd) return;
    SendMessageA(m_hWnd, LVM_DELETEALLITEMS, 0, 0);
}

void PacketListView::setApplicationFilter(const std::string& appName)
{
    m_currentAppFilter = appName;
}

void PacketListView::rebuildFromPacketStore(
    size_t totalPackets,
    std::function<bool(size_t, std::vector<std::string>&)> getMetaFunc)
{
    clear();

    for (size_t i = 0; i < totalPackets; ++i) {
        std::vector<std::string> meta;
        if (!getMetaFunc(i, meta)) continue;

        if (!shouldShowPacket(meta)) continue;

        int itemIndex = (int)SendMessageA(m_hWnd, LVM_GETITEMCOUNT, 0, 0);
        LVITEMA it{};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = itemIndex;
        it.lParam = (LPARAM)i;

        char idbuf[32];
        snprintf(idbuf, sizeof(idbuf), "%d", (int)i);
        it.pszText = idbuf;

        SendMessageA(m_hWnd, LVM_INSERTITEMA, 0, (LPARAM)&it);

        for (int c = 0; c < (int)meta.size() && c < 9; ++c) {
            LVITEMA sub{};
            sub.mask = LVIF_TEXT;
            sub.iItem = itemIndex;
            sub.iSubItem = c + 1;
            sub.pszText = const_cast<char*>(meta[c].c_str());
            SendMessageA(m_hWnd, LVM_SETITEMA, 0, (LPARAM)&sub);
        }
    }
}
