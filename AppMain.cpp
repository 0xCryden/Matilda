// AppMain.cpp - main application class
#include "framework.h"
#include "Matilda.h"
#include "AppMain.h"

#include <windows.h>
#include <windowsx.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")

#include <string>
#include <memory>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>

#include "Logger.h"
#include "CaptureManager.h"

#define MAX_LOADSTRING 100

// parse a hex string like "de ad be ef" or "deadbeef" into bytes. Returns false on invalid chars.
static bool parseHexString(const std::string& s, std::vector<uint8_t>& out)
{
    out.clear();
    std::string tmp;
    for (char c : s) { if (!isspace((unsigned char)c)) tmp.push_back(c); }
    if (tmp.size() % 2 != 0) return false;
    for (size_t i = 0; i < tmp.size(); i += 2)
    {
        char high = tmp[i]; char low = tmp[i + 1];
        auto hexval = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
            };
        int hi = hexval(high); int lo = hexval(low);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

static std::string bytesToHexString(const std::vector<uint8_t>& b)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t x : b) ss << std::setw(2) << (int)x;
    return ss.str();
}

// ---------------------------------------------------------------------------
// Packet field parser — Ethernet / IPv4 / TCP / UDP
// ---------------------------------------------------------------------------
/*static*/
std::vector<ParsedField> MainApp::ParsePacketFields(const std::vector<uint8_t>& b)
{
    std::vector<ParsedField> fields;
    if (b.size() < 14) return fields;

    auto addField = [&](const char* layer, const char* name, size_t off, size_t len, const std::string& val) {
        ParsedField f;
        f.layerTag = layer;
        f.name = name;
        f.byteOffset = off;
        f.byteLen = len;
        f.value = val;
        fields.push_back(f);
        };
    auto u8 = [&](size_t o) -> uint8_t { return b[o]; };
    auto u16 = [&](size_t o) -> uint16_t { return (uint16_t)((b[o] << 8) | b[o + 1]); };
    auto u32 = [&](size_t o) -> uint32_t { return ((uint32_t)b[o] << 24) | ((uint32_t)b[o + 1] << 16) | ((uint32_t)b[o + 2] << 8) | b[o + 3]; };
    auto hex2 = [&](size_t o) -> std::string {
        char buf[8]; snprintf(buf, sizeof(buf), "%02X", b[o]); return buf;
        };
    auto mac = [&](size_t o) -> std::string {
        char buf[24];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5]);
        return buf;
        };
    auto ip4 = [&](size_t o) -> std::string {
        char buf[24]; snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[o], b[o + 1], b[o + 2], b[o + 3]); return buf;
        };
    auto dec16 = [&](uint16_t v) -> std::string { return std::to_string(v); };
    auto dec32 = [&](uint32_t v) -> std::string { return std::to_string(v); };

    // --- Ethernet (14 bytes) ---
    addField("ETH", "Dst MAC", 0, 6, mac(0));
    addField("ETH", "Src MAC", 6, 6, mac(6));
    uint16_t ethType = u16(12);
    {
        char buf[32]; snprintf(buf, sizeof(buf), "0x%04X", ethType); addField("ETH", "EtherType", 12, 2, buf);
    }

    if (ethType != 0x0800 || b.size() < 14 + 20) return fields;

    // --- IPv4 ---
    size_t ip = 14;
    uint8_t verIhl = u8(ip);
    addField("IP", "Version", ip + 0, 1, std::to_string((verIhl >> 4) & 0xF));
    addField("IP", "IHL (words)", ip + 0, 1, std::to_string(verIhl & 0xF));
    addField("IP", "DSCP/ECN", ip + 1, 1, hex2(ip + 1));
    addField("IP", "Total Len", ip + 2, 2, dec16(u16(ip + 2)));
    addField("IP", "ID", ip + 4, 2, [&] { char b2[16]; snprintf(b2, sizeof(b2), "0x%04X", u16(ip + 4)); return std::string(b2); }());
    uint16_t frag = u16(ip + 6);
    {
        char buf[32]; snprintf(buf, sizeof(buf), "0x%04X (DF=%d MF=%d off=%d)", frag, (frag >> 14) & 1, (frag >> 13) & 1, frag & 0x1FFF);
        addField("IP", "Flags/Fragment", ip + 6, 2, buf);
    }
    addField("IP", "TTL", ip + 8, 1, dec16(u8(ip + 8)));
    uint8_t proto = u8(ip + 9);
    {
        std::string ps = std::to_string(proto);
        if (proto == 6) ps += " (TCP)"; else if (proto == 17) ps += " (UDP)"; else if (proto == 1) ps += " (ICMP)";
        addField("IP", "Protocol", ip + 9, 1, ps);
    }
    {
        char buf[16]; snprintf(buf, sizeof(buf), "0x%04X", u16(ip + 10)); addField("IP", "Header Checksum", ip + 10, 2, buf);
    }
    addField("IP", "Src IP", ip + 12, 4, ip4(ip + 12));
    addField("IP", "Dst IP", ip + 16, 4, ip4(ip + 16));

    size_t ihl = (size_t)(verIhl & 0x0F) * 4;
    if (ihl < 20) ihl = 20;
    if (b.size() < ip + ihl) return fields;

    size_t tp = ip + ihl; // transport offset

    // --- TCP ---
    if (proto == 6 && b.size() >= tp + 20)
    {
        addField("TCP", "Src Port", tp + 0, 2, dec16(u16(tp + 0)));
        addField("TCP", "Dst Port", tp + 2, 2, dec16(u16(tp + 2)));
        addField("TCP", "Seq Num", tp + 4, 4, dec32(u32(tp + 4)));
        addField("TCP", "Ack Num", tp + 8, 4, dec32(u32(tp + 8)));
        uint8_t dataOff = (u8(tp + 12) >> 4) & 0xF;
        addField("TCP", "Data Offset", tp + 12, 1, std::to_string(dataOff) + " (" + std::to_string(dataOff * 4) + " bytes)");
        uint8_t flags = u8(tp + 13);
        {
            char buf[64]; snprintf(buf, sizeof(buf), "0x%02X [%s%s%s%s%s%s]", flags,
                (flags & 0x20) ? "URG " : "", (flags & 0x10) ? "ACK " : "", (flags & 0x08) ? "PSH " : "",
                (flags & 0x04) ? "RST " : "", (flags & 0x02) ? "SYN " : "", (flags & 0x01) ? "FIN " : "");
            addField("TCP", "Flags", tp + 13, 1, buf);
        }
        addField("TCP", "Window", tp + 14, 2, dec16(u16(tp + 14)));
        { char buf[16]; snprintf(buf, sizeof(buf), "0x%04X", u16(tp + 16)); addField("TCP", "Checksum", tp + 16, 2, buf); }
        addField("TCP", "Urgent Ptr", tp + 18, 2, dec16(u16(tp + 18)));
        size_t tcpHdrLen = (size_t)dataOff * 4; if (tcpHdrLen < 20) tcpHdrLen = 20;
        size_t payOff = tp + tcpHdrLen;
        if (payOff < b.size())
            addField("TCP", "Payload", payOff, b.size() - payOff,
                "[" + std::to_string(b.size() - payOff) + " bytes]");
    }
    // --- UDP ---
    else if (proto == 17 && b.size() >= tp + 8)
    {
        addField("UDP", "Src Port", tp + 0, 2, dec16(u16(tp + 0)));
        addField("UDP", "Dst Port", tp + 2, 2, dec16(u16(tp + 2)));
        addField("UDP", "Length", tp + 4, 2, dec16(u16(tp + 4)));
        { char buf[16]; snprintf(buf, sizeof(buf), "0x%04X", u16(tp + 6)); addField("UDP", "Checksum", tp + 6, 2, buf); }
        if (b.size() > tp + 8)
            addField("UDP", "Payload", tp + 8, b.size() - (tp + 8),
                "[" + std::to_string(b.size() - (tp + 8)) + " bytes]");
    }

    return fields;
}

// ---------------------------------------------------------------------------
// Update the parsed panel with a new packet
// ---------------------------------------------------------------------------
void MainApp::UpdateParsedPanel(const std::vector<uint8_t>& bytes)
{
    m_currentBytes = bytes;
    m_parsedFields = ParsePacketFields(bytes);
    m_hoveredField = -1;
    if (m_parsedPanel) InvalidateRect(m_parsedPanel, nullptr, TRUE);
}

// ---------------------------------------------------------------------------
// Paint the parsed panel
// ---------------------------------------------------------------------------
void MainApp::PaintParsedPanel(HDC hdc, const RECT& rc)
{
    // Background
    HBRUSH bgBrush = CreateSolidBrush(RGB(250, 250, 252));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    if (m_parsedFields.empty())
    {
        SetTextColor(hdc, RGB(160, 160, 160));
        SetBkMode(hdc, TRANSPARENT);
        const char* msg = "No packet selected";
        TextOutA(hdc, rc.left + 8, rc.top + 8, msg, (int)strlen(msg));
        return;
    }

    HFONT monoFont = CreateFontA(
        -13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    HFONT hdrFont = CreateFontA(
        -12, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    // Column split: label takes 40% of width
    int colSplit = rc.left + (rc.right - rc.left) * 42 / 100;
    int rowH = PARSED_ROW_H;
    int y = rc.top - GetScrollPos(m_parsedPanel, SB_VERT) * rowH;

    std::string lastLayer;
    int rowIndex = 0;

    for (int fi = 0; fi < (int)m_parsedFields.size(); ++fi)
    {
        const ParsedField& f = m_parsedFields[fi];
        bool collapsed = (m_collapsedLayers.count(f.layerTag) > 0);

        // Layer header row
        if (f.layerTag != lastLayer)
        {
            lastLayer = f.layerTag;
            if (y + rowH > rc.top && y < rc.bottom)
            {
                RECT headerRect = { rc.left, y, rc.right, y + rowH };
                COLORREF hdrColor =
                    (f.layerTag == "ETH") ? RGB(210, 228, 255) :
                    (f.layerTag == "IP") ? RGB(210, 255, 215) :
                    (f.layerTag == "TCP") ? RGB(255, 235, 210) :
                    (f.layerTag == "UDP") ? RGB(255, 215, 230) :
                    RGB(230, 230, 230);
                HBRUSH hdrBrush = CreateSolidBrush(hdrColor);
                FillRect(hdc, &headerRect, hdrBrush);
                DeleteObject(hdrBrush);
                SelectObject(hdc, hdrFont);
                SetTextColor(hdc, RGB(40, 40, 40));
                SetBkMode(hdc, TRANSPARENT);
                // collapse triangle: ▶ (collapsed) or ▼ (expanded)
                const char* tri = collapsed ? "\xE2\x96\xB6" : "\xE2\x96\xBC"; // UTF-8, fallback below
                // Use simple ASCII proxies since EDIT control is ANSI
                std::string hdrText = std::string(collapsed ? "> " : "v ") + f.layerTag;
                TextOutA(hdc, rc.left + 4, y + 2, hdrText.c_str(), (int)hdrText.size());
                // bottom border
                HPEN pen = CreatePen(PS_SOLID, 1, RGB(180, 180, 190));
                HPEN old = (HPEN)SelectObject(hdc, pen);
                MoveToEx(hdc, rc.left, y + rowH - 1, nullptr);
                LineTo(hdc, rc.right, y + rowH - 1);
                SelectObject(hdc, old); DeleteObject(pen);
            }
            y += rowH;
            rowIndex++;
        }

        // Skip field rows if layer is collapsed
        if (collapsed) continue;

        if (y + rowH <= rc.top) { y += rowH; rowIndex++; continue; }
        if (y >= rc.bottom) { break; }

        RECT rowRect = { rc.left, y, rc.right, y + rowH };

        // Hover / highlight
        bool hovered = (fi == m_hoveredField);
        COLORREF rowBg = hovered ? RGB(198, 220, 255) : (rowIndex % 2 == 0 ? RGB(250, 250, 252) : RGB(243, 243, 248));
        HBRUSH rowBrush = CreateSolidBrush(rowBg);
        FillRect(hdc, &rowRect, rowBrush);
        DeleteObject(rowBrush);

        // Divider line between name/value columns
        HPEN divPen = CreatePen(PS_SOLID, 1, RGB(210, 210, 215));
        HPEN oldPen = (HPEN)SelectObject(hdc, divPen);
        MoveToEx(hdc, colSplit, y, nullptr);
        LineTo(hdc, colSplit, y + rowH);
        SelectObject(hdc, oldPen); DeleteObject(divPen);

        // Row bottom border (subtle)
        HPEN borderPen = CreatePen(PS_SOLID, 1, RGB(230, 230, 235));
        oldPen = (HPEN)SelectObject(hdc, borderPen);
        MoveToEx(hdc, rc.left, y + rowH - 1, nullptr);
        LineTo(hdc, rc.right, y + rowH - 1);
        SelectObject(hdc, oldPen); DeleteObject(borderPen);

        SelectObject(hdc, monoFont);
        SetBkMode(hdc, TRANSPARENT);

        // Field name (left column, slightly indented)
        SetTextColor(hdc, hovered ? RGB(0, 50, 150) : RGB(80, 80, 100));
        RECT nameRect = { rc.left + 6, y + 1, colSplit - 2, y + rowH };
        DrawTextA(hdc, f.name.c_str(), -1, &nameRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        // Field value (right column)
        SetTextColor(hdc, hovered ? RGB(0, 80, 0) : RGB(30, 30, 30));
        RECT valRect = { colSplit + 4, y + 1, rc.right - 2, y + rowH };
        DrawTextA(hdc, f.value.c_str(), -1, &valRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        y += rowH;
        rowIndex++;
    }

    DeleteObject(monoFont);
    DeleteObject(hdrFont);
}

// ---------------------------------------------------------------------------
// Highlight bytes in the hex EDIT that correspond to a field
// ---------------------------------------------------------------------------
void MainApp::HighlightHexRange(size_t byteOffset, size_t byteLen)
{
    if (!m_packetDetail || m_currentBytes.empty()) return;
    // Fixed layout per line:
    //   offset "XXXXXXXX: "   = 10 chars
    //   hex    "XX " * 16     = 48 chars  (positions 10..57)
    //   gap    " "            =  1 char
    //   ascii  16 chars       (positions 59..74)
    //   "\r\n"                =  2 chars
    //   total line length     = 77 chars  (lineLen)
    const int lineLen = 77; // 10 + 48 + 1 + 16 + 2
    const int hexColStart = 10; // start of "XX " bytes
    const int bytesPerLine = 16;

    auto byteToHexChar = [&](size_t b) -> int {
        int line = (int)(b / bytesPerLine);
        int col = (int)(b % bytesPerLine);
        return line * lineLen + hexColStart + col * 3; // "XX " -> 3 chars each
        };

    if (byteLen == 0) return;
    int selStart = byteToHexChar(byteOffset);
    // end: last byte's "XX" (2 chars, no trailing space included in selection)
    size_t lastByte = byteOffset + byteLen - 1;
    int selEnd = byteToHexChar(lastByte) + 2;

    // If range spans multiple lines we extend to cover all intermediate bytes
    // (the selection will also cover the gap/ascii area in between, which is
    //  acceptable — the important thing is the first and last byte are highlighted)
    SendMessageA(m_packetDetail, EM_SETSEL, (WPARAM)selStart, (LPARAM)selEnd);
    SendMessageA(m_packetDetail, EM_SCROLLCARET, 0, 0);
}

// ---------------------------------------------------------------------------
// Parsed panel window proc (static trampoline)
// ---------------------------------------------------------------------------
/*static*/
LRESULT CALLBACK MainApp::StaticParsedPanelProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    MainApp* pThis = nullptr;
    if (msg == WM_CREATE)
    {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        pThis = (MainApp*)cs->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    }
    else
    {
        pThis = (MainApp*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }
    if (pThis) return pThis->HandleParsedPanelMessage(hWnd, msg, wParam, lParam);
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Parsed panel message handler
// ---------------------------------------------------------------------------
LRESULT MainApp::HandleParsedPanelMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc; GetClientRect(hWnd, &rc);
        PaintParsedPanel(hdc, rc);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1; // handled in WM_PAINT

    case WM_MOUSEMOVE:
    {
        int mx = GET_X_LPARAM(lParam);
        int my = GET_Y_LPARAM(lParam);

        TRACKMOUSEEVENT tme{};
        tme.cbSize = sizeof(tme);
        tme.dwFlags = TME_LEAVE;
        tme.hwndTrack = hWnd;
        TrackMouseEvent(&tme);

        // Replicate y-accumulation from PaintParsedPanel (respecting collapsed layers)
        int scrollY = GetScrollPos(hWnd, SB_VERT);
        int rowH = PARSED_ROW_H;
        int y = -scrollY * rowH;
        std::string lastLayer;
        int hitField = -1;
        for (int fi = 0; fi < (int)m_parsedFields.size(); ++fi)
        {
            const ParsedField& f = m_parsedFields[fi];
            bool collapsed = (m_collapsedLayers.count(f.layerTag) > 0);
            if (f.layerTag != lastLayer) { lastLayer = f.layerTag; y += rowH; } // header row
            if (collapsed) continue;
            if (my >= y && my < y + rowH) { hitField = fi; break; }
            y += rowH;
        }

        if (hitField != m_hoveredField)
        {
            m_hoveredField = hitField;
            InvalidateRect(hWnd, nullptr, TRUE);

            if (hitField >= 0)
                HighlightHexRange(m_parsedFields[hitField].byteOffset,
                    m_parsedFields[hitField].byteLen);

            if (m_parsedTooltip && hitField >= 0)
            {
                TOOLINFOA ti{};
                ti.cbSize = sizeof(TOOLINFOA);
                ti.uFlags = TTF_SUBCLASS;
                ti.hwnd = hWnd;
                ti.uId = 1;
                RECT rc; GetClientRect(hWnd, &rc);
                ti.rect = rc;
                ti.lParam = (LPARAM)hitField;
                SendMessageA(m_parsedTooltip, TTM_UPDATETIPTEXTA, 0, (LPARAM)&ti);
            }
        }
        return 0;
    }
    case WM_LBUTTONDOWN:
    {
        // Check if click landed on a layer header row — if so, toggle collapse
        int mx = GET_X_LPARAM(lParam);
        int my = GET_Y_LPARAM(lParam);
        (void)mx;
        int scrollY = GetScrollPos(hWnd, SB_VERT);
        int rowH = PARSED_ROW_H;
        int y = -scrollY * rowH;
        std::string lastLayer;
        for (int fi = 0; fi < (int)m_parsedFields.size(); ++fi)
        {
            const ParsedField& f = m_parsedFields[fi];
            if (f.layerTag != lastLayer)
            {
                lastLayer = f.layerTag;
                // Is the click within this header row?
                if (my >= y && my < y + rowH)
                {
                    if (m_collapsedLayers.count(f.layerTag))
                        m_collapsedLayers.erase(f.layerTag);
                    else
                        m_collapsedLayers.insert(f.layerTag);
                    m_hoveredField = -1;
                    InvalidateRect(hWnd, nullptr, TRUE);
                    return 0;
                }
                y += rowH;
            }
            if (m_collapsedLayers.count(f.layerTag) == 0)
                y += rowH; // field row only counted if layer not collapsed
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        if (m_hoveredField != -1)
        {
            m_hoveredField = -1;
            InvalidateRect(hWnd, nullptr, TRUE);
        }
        return 0;

    case WM_NOTIFY:
    {
        NMHDR* hdr = (NMHDR*)lParam;
        if (hdr && hdr->code == TTN_GETDISPINFOA && m_hoveredField >= 0)
        {
            NMTTDISPINFOA* di = (NMTTDISPINFOA*)lParam;
            static char tipBuf[256];
            const ParsedField& f = m_parsedFields[m_hoveredField];
            snprintf(tipBuf, sizeof(tipBuf), "%s  |  offset %zu, %zu byte%s",
                f.name.c_str(), f.byteOffset, f.byteLen, f.byteLen == 1 ? "" : "s");
            di->lpszText = tipBuf;
        }
        return 0;
    }
    case WM_SIZE:
        InvalidateRect(hWnd, nullptr, TRUE);
        return 0;

    case WM_VSCROLL:
    {
        SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_ALL;
        GetScrollInfo(hWnd, SB_VERT, &si);
        int newPos = si.nPos;
        switch (LOWORD(wParam)) {
        case SB_TOP:         newPos = si.nMin; break;
        case SB_BOTTOM:      newPos = si.nMax; break;
        case SB_LINEUP:      newPos--; break;
        case SB_LINEDOWN:    newPos++; break;
        case SB_PAGEUP:      newPos -= si.nPage; break;
        case SB_PAGEDOWN:    newPos += si.nPage; break;
        case SB_THUMBTRACK:  newPos = si.nTrackPos; break;
        }
        if (newPos < si.nMin) newPos = si.nMin;
        if (newPos > (int)(si.nMax - (int)si.nPage + 1)) newPos = si.nMax - (int)si.nPage + 1;
        si.fMask = SIF_POS; si.nPos = newPos;
        SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
        InvalidateRect(hWnd, nullptr, TRUE);
        return 0;
    }
    case WM_MOUSEWHEEL:
    {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        int lines = delta / WHEEL_DELTA;
        SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_ALL;
        GetScrollInfo(hWnd, SB_VERT, &si);
        int newPos = si.nPos - lines;
        if (newPos < si.nMin) newPos = si.nMin;
        if (newPos > (int)(si.nMax - (int)si.nPage + 1)) newPos = si.nMax - (int)si.nPage + 1;
        si.fMask = SIF_POS; si.nPos = newPos;
        SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
        InvalidateRect(hWnd, nullptr, TRUE);
        return 0;
    }
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}



void MainApp::PopulateProcessCombo(HWND combo)
{
    if (!combo) return;
    std::unordered_set<std::string> seen;
    DWORD cbNeeded = 0;
    DWORD aProcesses[1024] = { 0 };
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return;
    DWORD count = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < count; ++i)
    {
        DWORD pid = aProcesses[i];
        if (pid == 0) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;
        char buf[MAX_PATH]; DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameA(h, 0, buf, &sz))
        {
            const char* name = buf;
            const char* p = strrchr(buf, '\\');
            if (p) name = p + 1;
            if (name && name[0])
            {
                std::string sname = name;
                if (sname == "All Applications") { CloseHandle(h); continue; }
                if (seen.find(sname) != seen.end()) { CloseHandle(h); continue; }
                seen.insert(sname);
                if (SendMessageA(combo, CB_FINDSTRINGEXACT, -1, (LPARAM)sname.c_str()) == CB_ERR)
                    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)sname.c_str());
            }
        }
        CloseHandle(h);
    }
}

void MainApp::AppendText(const std::string& text)
{
    if (!m_outputBox) return;
    int len = GetWindowTextLengthA(m_outputBox);
    SendMessageA(m_outputBox, EM_SETSEL, len, len);
    SendMessageA(m_outputBox, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
}

void MainApp::SetupListViewColumns()
{
    if (!m_packetList) return;
    LVCOLUMNA col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = (LPSTR)"ID"; col.cx = 50; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
    col.pszText = (LPSTR)"TIME"; col.cx = 120; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
    col.pszText = (LPSTR)"DIR"; col.cx = 60; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
    col.pszText = (LPSTR)"PROTO"; col.cx = 60; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
    col.pszText = (LPSTR)"SRC"; col.cx = 140; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 4, (LPARAM)&col);
    col.pszText = (LPSTR)"S PORT"; col.cx = 60; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 5, (LPARAM)&col);
    col.pszText = (LPSTR)"DST"; col.cx = 140; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 6, (LPARAM)&col);
    col.pszText = (LPSTR)"D PORT"; col.cx = 60; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 7, (LPARAM)&col);
    col.pszText = (LPSTR)"LEN"; col.cx = 60; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 8, (LPARAM)&col);
    col.pszText = (LPSTR)"PROC"; col.cx = 140; SendMessageA(m_packetList, LVM_INSERTCOLUMNA, 9, (LPARAM)&col);

    // enable full-row select so clicking any column selects the item
    ListView_SetExtendedListViewStyle(m_packetList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

// Parameters passed to listview compare routine
struct LVSortParams { HWND hwnd; int col; bool desc; };

// Compare callback used by ListView_SortItems. lParam1/lParam2 are the item lParams previously set
static int CALLBACK ListViewCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    LVSortParams* p = (LVSortParams*)lParamSort;
    if (!p || !p->hwnd) return 0;

    LVFINDINFO fi{};
    fi.flags = LVFI_PARAM;

    fi.lParam = lParam1;
    int idx1 = ListView_FindItem(p->hwnd, -1, &fi);

    fi.lParam = lParam2;
    int idx2 = ListView_FindItem(p->hwnd, -1, &fi);

    wchar_t buf1[512] = { 0 }, buf2[512] = { 0 };

    if (idx1 != -1)
        ListView_GetItemText(p->hwnd, idx1, p->col, buf1, _countof(buf1));

    if (idx2 != -1)
        ListView_GetItemText(p->hwnd, idx2, p->col, buf2, _countof(buf2));

    std::wstring s1 = buf1;
    std::wstring s2 = buf2;

    int cmp = 0;

    // numeric columns: ID(0), S PORT(5), D PORT(7), LEN(8)
    if (p->col == 0 || p->col == 5 || p->col == 7 || p->col == 8)
    {
        long v1 = 0, v2 = 0;

        try { v1 = std::stol(s1); }
        catch (...) { v1 = 0; }
        try { v2 = std::stol(s2); }
        catch (...) { v2 = 0; }

        if (v1 < v2) cmp = -1;
        else if (v1 > v2) cmp = 1;
        else cmp = 0;
    }
    else
    {
        cmp = _wcsicmp(s1.c_str(), s2.c_str()); // wide-char version
    }

    if (p->desc) cmp = -cmp;
    return cmp;
}

void MainApp::RepositionControls(int clientW, int clientH)
{
    const int margin = 10;
    const int topArea = 40;
    const int bottomControlsHeight = 100; // space reserved for bottom controls

    if (m_splitPos <= 0) m_splitPos = margin + 200;
    int minLeft = 100;
    int maxLeft = clientW - 300;
    if (maxLeft < minLeft) maxLeft = minLeft;
    if (m_splitPos < minLeft) m_splitPos = minLeft;
    if (m_splitPos > maxLeft) m_splitPos = maxLeft;

    int leftX = margin;
    int leftW = m_splitPos - margin;
    int rightX = m_splitPos + m_splitWidth; // splitter width
    int rightW = clientW - rightX - margin;

    int listTop = topArea;
    int bottomTop = clientH - bottomControlsHeight;
    int availableHeight = bottomTop - listTop;
    if (availableHeight < 140) availableHeight = 140; // ensure minimum area

    if (m_hsplitPos <= 0) m_hsplitPos = listTop + (availableHeight * 70) / 100; // default: 70% list
    // clamp horizontal splitter between reasonable limits
    int minListHeight = 80;
    int maxListTop = listTop + availableHeight - minListHeight - m_hsplitHeight;
    if (m_hsplitPos < listTop + minListHeight) m_hsplitPos = listTop + minListHeight;
    if (m_hsplitPos > maxListTop) m_hsplitPos = maxListTop;

    int listHeight = m_hsplitPos - listTop;
    // preview controls moved to bottom toolbar; full list height available
    int listHeightAdjusted = listHeight;
    if (listHeightAdjusted < 80) listHeightAdjusted = 80;
    int detailHeight = availableHeight - listHeightAdjusted - m_hsplitHeight;
    if (detailHeight < 60) detailHeight = 60;

    // Move windows if they exist
    if (m_outputBox) MoveWindow(m_outputBox, leftX, listTop, leftW, bottomTop - listTop, TRUE);
    if (m_packetList) MoveWindow(m_packetList, rightX, listTop, rightW, listHeightAdjusted, TRUE);

    // Detail area: split horizontally into hex-dump (left) | detail-splitter | parsed-fields (right)
    int detailTop = listTop + listHeightAdjusted + m_hsplitHeight;

    // Clamp detail splitter within the right pane width
    int minDetailLeft = 80;
    int maxDetailLeft = rightW - 80 - m_detailSplitWidth;
    if (maxDetailLeft < minDetailLeft) maxDetailLeft = minDetailLeft;
    if (m_detailSplitPos <= 0) m_detailSplitPos = rightW / 2;
    if (m_detailSplitPos < minDetailLeft) m_detailSplitPos = minDetailLeft;
    if (m_detailSplitPos > maxDetailLeft) m_detailSplitPos = maxDetailLeft;

    int hexW = m_detailSplitPos;
    int parsedX = rightX + m_detailSplitPos + m_detailSplitWidth;
    int parsedW = rightW - m_detailSplitPos - m_detailSplitWidth;
    if (parsedW < 60) parsedW = 60;

    if (m_packetDetail)
        MoveWindow(m_packetDetail, rightX, detailTop, hexW, detailHeight, TRUE);
    if (m_parsedPanel)
    {
        MoveWindow(m_parsedPanel, parsedX, detailTop, parsedW, detailHeight, TRUE);
        // Update scroll range based on total rows
        int totalRows = 0;
        std::string lastLayer;
        for (auto& f : m_parsedFields) {
            if (f.layerTag != lastLayer) { lastLayer = f.layerTag; totalRows++; }
            totalRows++;
        }
        int visRows = detailHeight / PARSED_ROW_H;
        SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_RANGE | SIF_PAGE;
        si.nMin = 0; si.nMax = (totalRows > 0) ? totalRows - 1 : 0; si.nPage = (visRows > 0) ? visRows : 1;
        SetScrollInfo(m_parsedPanel, SB_VERT, &si, TRUE);
    }

    // Top controls
    if (m_appCombo) MoveWindow(m_appCombo, leftX, 10, leftW, 24, TRUE);
    if (m_deviceCombo) {
        int deviceComboW = rightW - 120; if (deviceComboW < 120) deviceComboW = 120;
        MoveWindow(m_deviceCombo, rightX, 10, deviceComboW, 24, TRUE);
    }
    HWND btnStart = GetDlgItem(m_mainWindow, 1);
    if (btnStart) MoveWindow(btnStart, clientW - 110 - margin, 10, 100, 24, TRUE);

    // Bottom row 1: [Replay Last] | [proto][srcPort][dstIp][dstPort][payload][Hex] | [Send Custom]
    const int btnReplayW = 100;
    const int btnSendW = 130;
    const int row1Y = bottomTop + 8;
    HWND btnReplay = GetDlgItem(m_mainWindow, 4);
    if (btnReplay) MoveWindow(btnReplay, leftX, row1Y, btnReplayW, 24, TRUE);
    HWND btnSend = GetDlgItem(m_mainWindow, 6);
    if (btnSend) MoveWindow(btnSend, clientW - btnSendW - margin, row1Y, btnSendW, 24, TRUE);

    // preview controls fill the space between Replay Last and Send Custom
    {
        int previewX = leftX + btnReplayW + 6;
        int previewEnd = clientW - btnSendW - margin - 6;
        int totalPreviewW = previewEnd - previewX;
        if (totalPreviewW < 100) totalPreviewW = 100;
        // fixed widths: proto, srcPort, dstIp, dstPort; payload expands to fill remaining space
        const int wProto = 72, wSrcPort = 58, wDstIp = 120, wDstPort = 58;
        const int gaps = 3 * 4; // 3 gaps of 4 px between the 4 fixed controls
        int wPayload = totalPreviewW - wProto - wSrcPort - wDstIp - wDstPort - gaps;
        if (wPayload < 60) wPayload = 60;
        int cx = previewX;
        if (m_previewProtoCombo) { MoveWindow(m_previewProtoCombo, cx, row1Y, wProto, 24, TRUE); cx += wProto + 4; }
        if (m_previewSrcPort) { MoveWindow(m_previewSrcPort, cx, row1Y, wSrcPort, 24, TRUE); cx += wSrcPort + 4; }
        if (m_previewDstIp) { MoveWindow(m_previewDstIp, cx, row1Y, wDstIp, 24, TRUE); cx += wDstIp + 4; }
        if (m_previewDstPort) { MoveWindow(m_previewDstPort, cx, row1Y, wDstPort, 24, TRUE); cx += wDstPort + 4; }
        if (m_previewPayload) { MoveWindow(m_previewPayload, cx, row1Y, wPayload, 24, TRUE); }
    }

    // Bottom row 2: [Apply Filter] (filter text input removed)
    HWND btnFilter = GetDlgItem(m_mainWindow, 8);
    if (btnFilter) MoveWindow(btnFilter, leftX, bottomTop + 40, 120, 24, TRUE);
}

void MainApp::PopulateDeviceList()
{
    if (!m_captureManager || !m_deviceCombo) return;
    auto devs = m_captureManager->getDeviceList();
    for (const auto& d : devs)
        SendMessageA(m_deviceCombo, CB_ADDSTRING, 0, (LPARAM)d.c_str());
    if (!devs.empty()) SendMessageA(m_deviceCombo, CB_SETCURSEL, 0, 0);
}

void MainApp::OnStartCapture()
{
    if (m_capturing || !m_captureManager) return;
    m_capturing = true;
    m_logger->log("Starting capture...\r\n");
    HWND btnStart = GetDlgItem(m_mainWindow, 1);
    if (btnStart) SetWindowTextA(btnStart, "Stop capture");
    int sel = (int)SendMessageA(m_deviceCombo, CB_GETCURSEL, 0, 0);
    if (sel == CB_ERR) sel = 0;
    // capture start: device is opened inside start()
    m_captureManager->start([this](const std::string& s, int) {
        if (m_logger) m_logger->log(s);
        }, sel, m_mainWindow);
}

void MainApp::OnStopCapture()
{
    if (!m_capturing || !m_captureManager) return;
    m_capturing = false;
    m_logger->log("Stopping capture...\r\n");
    HWND btnStart = GetDlgItem(m_mainWindow, 1);
    if (btnStart) SetWindowTextA(btnStart, "Start capture");
    m_captureManager->stop();
}

MainApp::MainApp(HINSTANCE hInstance)
    : hInst(hInstance)
    , m_capturing(false)
    , m_sortCol(-1), m_sortDesc(false)
    , m_parsedPanel(nullptr), m_parsedTooltip(nullptr)
    , m_detailSplitPos(0), m_detailSplitWidth(6), m_detailSplitDragging(false)
    , m_hoveredField(-1)
    , m_theme(Themes::White())
{
}

int MainApp::Run(int nCmdShow)
{
    LoadStringW(hInst, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInst, IDC_MATILDA, szWindowClass, MAX_LOADSTRING);

    WNDCLASSEXW wcex{};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = MainApp::StaticWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInst;
    wcex.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_MATILDA));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr; // menu created programmatically below
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    RegisterClassExW(&wcex);

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 800, 600, nullptr, nullptr, hInst, this);

    m_mainWindow = hWnd;

    // Build "Settings > Theme >" menu programmatically
    {
        HMENU hTheme = CreatePopupMenu();
        AppendMenuW(hTheme, MF_STRING, IDM_THEME_WHITE, L"White");
        AppendMenuW(hTheme, MF_STRING, IDM_THEME_DARK, L"Dark");

        HMENU hSettings = CreatePopupMenu();
        AppendMenuW(hSettings, MF_POPUP, (UINT_PTR)hTheme, L"Theme");

        HMENU hMenuBar = CreateMenu();
        AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hSettings, L"Settings");

        SetMenu(hWnd, hMenuBar);
    }

    int margin = 10;
    int initialW = 800;
    int initialTop = 40;
    int leftW = 200;
    int rightX = margin + leftW + margin;
    int rightW = initialW - rightX - margin;

    m_outputBox = CreateWindowA("EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
        margin, initialTop, leftW, 420,
        hWnd, nullptr, hInst, nullptr);

    // vertical splitter between left (output) and right (packet list)
    m_splitPos = margin + leftW;
    m_splitWidth = 8;
    m_vsplitDragging = false;

    // horizontal splitter between list and hex/detail within right pane
    m_hsplitHeight = 6;
    m_hsplitPos = initialTop + 360;
    m_hsplitDragging = false;

    m_packetList = CreateWindowExA(0, WC_LISTVIEWA, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | WS_VSCROLL,
        rightX, initialTop, rightW, 360,
        hWnd, (HMENU)9, hInst, nullptr);

    // preview/send controls (now in the bottom toolbar, not overlapping the list)
    m_previewProtoCombo = CreateWindowExA(WS_EX_CLIENTEDGE, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 80, 200,
        hWnd, (HMENU)12, hInst, nullptr);
    if (m_previewProtoCombo) {
        SendMessageA(m_previewProtoCombo, CB_ADDSTRING, 0, (LPARAM)"TCP");
        SendMessageA(m_previewProtoCombo, CB_ADDSTRING, 0, (LPARAM)"UDP");
        SendMessageA(m_previewProtoCombo, CB_SETCURSEL, 0, 0);
    }
    m_previewSrcPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 60, 24,
        hWnd, (HMENU)13, hInst, nullptr);
    m_previewDstIp = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 130, 24,
        hWnd, (HMENU)14, hInst, nullptr);
    m_previewDstPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 60, 24,
        hWnd, (HMENU)15, hInst, nullptr);
    m_previewPayload = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 160, 24,
        hWnd, (HMENU)16, hInst, nullptr);
    // Hex checkbox removed — payload field uses full available width

    m_packetDetail = CreateWindowA("EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL | WS_HSCROLL | ES_AUTOHSCROLL,
        rightX, initialTop + 360, rightW / 2, 120,
        hWnd, (HMENU)10, hInst, nullptr);

    // Register custom class for the parsed-fields panel (owner-drawn, no system background)
    {
        WNDCLASSEXA wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = MainApp::StaticParsedPanelProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr; // we paint everything in WM_PAINT
        wc.lpszClassName = "MatildaParsedPanel";
        RegisterClassExA(&wc); // ignore ERROR_CLASS_ALREADY_EXISTS on re-run
    }

    m_parsedPanel = CreateWindowExA(WS_EX_CLIENTEDGE, "MatildaParsedPanel", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL,
        rightX + rightW / 2 + m_detailSplitWidth, initialTop + 360, rightW / 2, 120,
        hWnd, (HMENU)18, hInst, this);

    // Create tooltip for parsed panel
    m_parsedTooltip = CreateWindowEx(0, TOOLTIPS_CLASS, nullptr,
        WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        m_parsedPanel, nullptr, hInst, nullptr);
    if (m_parsedTooltip)
    {
        SendMessage(m_parsedTooltip, TTM_SETMAXTIPWIDTH, 0, 400);
        TOOLINFO ti{};
        ti.cbSize = sizeof(TOOLINFO);
        ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
        ti.hwnd = m_parsedPanel;
        ti.uId = (UINT_PTR)m_parsedPanel;
        ti.lpszText = LPSTR_TEXTCALLBACK; // we fill in TTN_GETDISPINFOA
        RECT rc; GetClientRect(m_parsedPanel, &rc);
        ti.rect = rc;
        SendMessage(m_parsedTooltip, TTM_ADDTOOLA, 0, (LPARAM)&ti);
    }

    // vertical detail-area splitter: default at 50% of right pane width
    m_detailSplitPos = rightW / 2;
    m_detailSplitWidth = 6;
    m_detailSplitDragging = false;

    m_appCombo = CreateWindowA("COMBOBOX", "All Applications",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        margin, 10, leftW, 200,
        hWnd, (HMENU)11, hInst, nullptr);

    int deviceComboW = rightW - 120; if (deviceComboW < 120) deviceComboW = 120;
    m_deviceCombo = CreateWindowA("COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        rightX, 10, deviceComboW, 200,
        hWnd, (HMENU)3, hInst, nullptr);

    CreateWindowA("BUTTON", "Start capture",
        WS_CHILD | WS_VISIBLE,
        initialW - 110, 10, 100, 24,
        hWnd, (HMENU)1, hInst, nullptr);

    CreateWindowA("BUTTON", "Replay Last",
        WS_CHILD | WS_VISIBLE,
        10, 470, 100, 24,
        hWnd, (HMENU)4, hInst, nullptr);

    // edit #5 removed (was wide input next to Send Custom; preview controls now serve that role)

    CreateWindowA("BUTTON", "Send Custom",
        WS_CHILD | WS_VISIBLE,
        650, 470, 140, 24,
        hWnd, (HMENU)6, hInst, nullptr);

    // edit #7 removed (was filter input next to Apply Filter)

    CreateWindowA("BUTTON", "Apply Filter",
        WS_CHILD | WS_VISIBLE,
        10, 500, 120, 24,
        hWnd, (HMENU)8, hInst, nullptr);

    if (!hWnd) return FALSE;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    SetFocus(m_outputBox);

    m_logger.reset(new Logger(hWnd, m_outputBox));
    m_captureManager.reset(new CaptureManager());

    PopulateDeviceList();
    // log device count once at startup
    if (m_captureManager && m_logger)
    {
        auto devs = m_captureManager->getDeviceList();
        std::ostringstream s; s << "Found " << devs.size() << " capture devices\r\n";
        m_logger->log(s.str());
        // log device count once at startup
        if (!devs.empty())
        {
            // uiWindow is set when capture starts via start(); no pre-open needed
        }
    }
    m_logger->log("Application started\r\n");

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    SetupListViewColumns();

    // ensure controls are placed according to current window size
    RECT rc; GetClientRect(hWnd, &rc);
    RepositionControls(rc.right, rc.bottom);

    if (m_appCombo)
    {
        SendMessageA(m_appCombo, CB_ADDSTRING, 0, (LPARAM)"All Applications");
        SendMessageA(m_appCombo, CB_SETCURSEL, 0, 0);
    }

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

LRESULT MainApp::HandleMessage(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        int cmdId = LOWORD(wParam);
        if (cmdId == 1)
        {
            if (m_capturing)
                OnStopCapture();
            else
                OnStartCapture();
        }
        else if (cmdId == 4)
        {
            if (m_captureManager)
            {
                size_t cnt = m_captureManager->getCapturedCount();
                if (cnt > 0) m_captureManager->sendCapturedPacket(cnt - 1);
            }
        }
        else if (cmdId == 6)
        {
            // Send Custom button: use preview controls for overrides and payload (hex or ascii)
            if (m_captureManager)
            {
                int sel = ListView_GetNextItem(m_packetList, -1, LVNI_SELECTED);
                if (sel >= 0)
                {
                    wchar_t idbuf[64] = { 0 };
                    ListView_GetItemText(m_packetList, sel, 0, idbuf, _countof(idbuf));
                    int pktIdx = _wtoi(idbuf);

                    // read preview controls
                    char protoBuf[32] = { 0 };
                    char srcPortBuf[32] = { 0 };
                    char dstIpBuf[64] = { 0 };
                    char dstPortBuf[32] = { 0 };
                    char payloadBuf[8192] = { 0 };
                    if (m_previewProtoCombo) {
                        int ps = (int)SendMessageA(m_previewProtoCombo, CB_GETCURSEL, 0, 0);
                        if (ps != CB_ERR) SendMessageA(m_previewProtoCombo, CB_GETLBTEXT, ps, (LPARAM)protoBuf);
                    }
                    if (m_previewSrcPort) GetWindowTextA(m_previewSrcPort, srcPortBuf, sizeof(srcPortBuf));
                    if (m_previewDstIp) GetWindowTextA(m_previewDstIp, dstIpBuf, sizeof(dstIpBuf));
                    if (m_previewDstPort) GetWindowTextA(m_previewDstPort, dstPortBuf, sizeof(dstPortBuf));
                    if (m_previewPayload) GetWindowTextA(m_previewPayload, payloadBuf, sizeof(payloadBuf));
                    bool useHex = false;
                    if (m_previewHexCheckbox) useHex = (SendMessageA(m_previewHexCheckbox, BM_GETCHECK, 0, 0) == BST_CHECKED);

                    std::string protoStr = protoBuf;
                    std::string srcPortStr = srcPortBuf;
                    std::string dstIpStr = dstIpBuf;
                    std::string dstPortStr = dstPortBuf;
                    std::string payloadStr = payloadBuf;

                    std::vector<uint8_t> payloadBytes;
                    if (!payloadStr.empty()) {
                        if (useHex) {
                            if (!parseHexString(payloadStr, payloadBytes)) {
                                if (m_logger) m_logger->log("Invalid hex payload\r\n");
                                break;
                                // was continue before;
                            }
                        }
                        else {
                            payloadBytes.assign(payloadStr.begin(), payloadStr.end());
                        }
                    }

                    uint16_t srcPortOverride = 0, dstPortOverride = 0;
                    try { srcPortOverride = (uint16_t)std::stoi(srcPortStr); }
                    catch (...) { srcPortOverride = 0; }
                    try { dstPortOverride = (uint16_t)std::stoi(dstPortStr); }
                    catch (...) { dstPortOverride = 0; }

                    std::string err;
                    bool ok = m_captureManager->sendCapturedPacketWithPayload((size_t)pktIdx, payloadBytes, protoStr, std::string(), srcPortOverride, dstIpStr, dstPortOverride, &err);

                    // Build meta for logging
                    std::vector<std::string> meta;
                    // time
                    SYSTEMTIME st; GetLocalTime(&st);
                    char timestr[64]; snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                    meta.push_back(timestr);
                    meta.push_back(std::string("Sent"));
                    meta.push_back(protoStr.empty() ? std::string("OTHER") : protoStr);
                    // try to get src/dst from preview or original meta
                    std::vector<std::string> origMeta;
                    if (!m_captureManager->getCapturedMeta((size_t)pktIdx, origMeta)) origMeta.clear();
                    std::string metaSrcIp = (origMeta.size() > 3) ? origMeta[3] : std::string();
                    std::string metaSrcPort = (origMeta.size() > 4) ? origMeta[4] : std::string();
                    std::string metaDstIp = (origMeta.size() > 5) ? origMeta[5] : std::string();
                    std::string metaDstPort = (origMeta.size() > 6) ? origMeta[6] : std::string();
                    if (!srcPortStr.empty()) metaSrcPort = srcPortStr;
                    if (!dstIpStr.empty()) metaDstIp = dstIpStr;
                    if (!dstPortStr.empty()) metaDstPort = dstPortStr;
                    meta.push_back(metaSrcIp);
                    meta.push_back(metaSrcPort);
                    meta.push_back(metaDstIp);
                    meta.push_back(metaDstPort);
                    // estimate length: prefer provided payload length, else fall back to original captured packet size
                    size_t estimatedLen = 0;
                    if (!payloadBytes.empty()) estimatedLen = payloadBytes.size();
                    else {
                        std::vector<uint8_t> tempBytes;
                        if (m_captureManager->getCapturedPacketBytes((size_t)pktIdx, tempBytes)) estimatedLen = tempBytes.size();
                    }
                    meta.push_back(std::to_string(estimatedLen));
                    meta.push_back(std::string("(Matilda)")); // proc: manually sent

                    if (ok) {
                        // CaptureManager already called logOutgoingPacket internally with the real
                        // built frame. Retrieve the ID it was assigned so we can log it by number.
                        size_t newId = m_captureManager->getCapturedCount(); // count after add
                        if (newId > 0) newId--; // last index
                        if (m_logger) {
                            std::ostringstream ss;
                            ss << "Packet " << newId << " sent\r\n";
                            m_logger->log(ss.str());
                        }
                    }
                    else {
                        if (m_logger) {
                            std::ostringstream ss;
                            ss << "Failed to send packet: " << err << "\r\n";
                            m_logger->log(ss.str());
                        }
                        // Do NOT insert a failed send into the packet table — it would
                        // pollute the app combo and the packet list with error strings.
                    }
                }
            }
        }
        else if (cmdId == 8)
        {
            if (m_captureManager)
            {
                // filter text input removed; clicking Apply Filter clears any active capture filter
                m_captureManager->setFilter(std::string());
                if (m_logger) m_logger->log("Capture filter cleared\r\n");
            }
        }
        else if (cmdId == 11)
        {
            // app combo selection changed -> filter list view
            if (HIWORD(wParam) == CBN_SELCHANGE)
            {
                char selbuf[256] = { 0 };
                int sel = (int)SendMessageA(m_appCombo, CB_GETCURSEL, 0, 0);
                if (sel != CB_ERR)
                    SendMessageA(m_appCombo, CB_GETLBTEXT, sel, (LPARAM)selbuf);
                std::string selStr = selbuf;
                bool showAll = selStr.empty() || selStr == "All Applications";

                if (m_packetList)
                    ListView_DeleteAllItems(m_packetList);

                size_t cnt = m_captureManager ? m_captureManager->getCapturedCount() : 0;
                for (size_t i = 0; i < cnt; ++i)
                {
                    std::vector<std::string> meta;
                    if (!m_captureManager->getCapturedMeta(i, meta)) continue;
                    std::string proc = meta.size() > 8 ? meta[8] : std::string();
                    if (!showAll && proc != selStr) continue;

                    int itemIndex = (int)SendMessageA(m_packetList, LVM_GETITEMCOUNT, 0, 0);
                    LVITEMA it{};
                    it.mask = LVIF_TEXT | LVIF_PARAM;
                    it.iItem = itemIndex;
                    it.lParam = (LPARAM)i;
                    char idbuf[32];
                    snprintf(idbuf, sizeof(idbuf), "%d", (int)i);
                    it.pszText = idbuf;
                    SendMessageA(m_packetList, LVM_INSERTITEMA, 0, (LPARAM)&it);

                    for (int c = 0; c < (int)meta.size() && c < 9; ++c)
                    {
                        LVITEMA sub{};
                        sub.mask = LVIF_TEXT;
                        sub.iItem = itemIndex;
                        sub.iSubItem = c + 1;
                        sub.pszText = const_cast<char*>(meta[c].c_str());
                        SendMessageA(m_packetList, LVM_SETITEMA, 0, (LPARAM)&sub);
                    }
                }
            }
        }
    }
    break;
    case WM_APP + 1:
    {
        // Logger posts std::string* (caller allocates; receiver must delete)
        std::string* text = (std::string*)lParam;
        if (text) {
            AppendText(*text);
            delete text;
        }
    }
    break;
    case WM_APP + 2:
    {
        // CaptureManager posts an array of PktMsg { int idx; char* summary; }
        int postCount = (int)wParam;
        struct PktMsg { int idx; char* summary; };
        PktMsg* arr = (PktMsg*)lParam;
        if (arr && postCount > 0)
        {
            for (int i = 0; i < postCount; ++i)
            {
                char* summary = arr[i].summary;
                if (summary && summary[0])
                {
                    // parse tab-separated columns: TIME, DIR, PROTO, SRC, S PORT, DST, D PORT, LEN, PROC
                    std::vector<std::string> cols;
                    std::string s(summary);
                    size_t pos = 0;
                    while (true)
                    {
                        size_t tab = s.find('\t', pos);
                        if (tab == std::string::npos)
                        {
                            cols.push_back(s.substr(pos));
                            break;
                        }
                        cols.push_back(s.substr(pos, tab - pos));
                        pos = tab + 1;
                        if (pos >= s.size()) break;
                    }

                    // determine current app filter selection
                    bool shouldInsert = true;
                    std::string selStr;
                    if (m_appCombo)
                    {
                        int sel = (int)SendMessageA(m_appCombo, CB_GETCURSEL, 0, 0);
                        if (sel != CB_ERR)
                        {
                            char selbuf[256] = { 0 };
                            SendMessageA(m_appCombo, CB_GETLBTEXT, sel, (LPARAM)selbuf);
                            selStr = selbuf;
                        }
                    }
                    // if a specific app is selected, only insert matching packets
                    if (!selStr.empty() && selStr != "All Applications")
                    {
                        std::string proccol = cols.size() > 8 ? cols[8] : std::string();
                        while (!proccol.empty() && (proccol.back() == '\n' || proccol.back() == '\r')) proccol.pop_back();
                        if (proccol != selStr) shouldInsert = false;
                    }

                    if (shouldInsert)
                    {
                        // insert into ListView (ID column uses posted index)
                        int itemIndex = (int)SendMessageA(m_packetList, LVM_GETITEMCOUNT, 0, 0);
                        LVITEMA it{};
                        it.mask = LVIF_TEXT | LVIF_PARAM;
                        it.iItem = itemIndex;
                        it.lParam = (LPARAM)arr[i].idx;
                        char idbuf[32];
                        snprintf(idbuf, sizeof(idbuf), "%d", arr[i].idx);
                        it.pszText = idbuf;
                        SendMessageA(m_packetList, LVM_INSERTITEMA, 0, (LPARAM)&it);

                        // set subitems: cols[0] -> TIME (subitem 1), cols[1] -> DIR (subitem 2), etc.
                        for (int c = 0; c < (int)cols.size() && c < 9; ++c)
                        {
                            LVITEMA sub{};
                            sub.mask = LVIF_TEXT;
                            sub.iItem = itemIndex;
                            sub.iSubItem = c + 1; // shift by 1 because subitem 0 is the ID
                            sub.pszText = const_cast<char*>(cols[c].c_str());
                            SendMessageA(m_packetList, LVM_SETITEMA, 0, (LPARAM)&sub);
                        }
                    }

                    // update applications combo with process name (last column)
                    // Skip pseudo-entries: errors, manually-sent markers
                    if ((int)cols.size() > 8 && m_appCombo)
                    {
                        std::string proc = cols.size() > 8 ? cols[8] : std::string();
                        if (!proc.empty() && proc.back() == '\n') proc.pop_back();
                        if (!proc.empty() && proc.back() == '\r') proc.pop_back();
                        bool isRealProc = !proc.empty()
                            && proc.rfind("Error:", 0) != 0     // not an error string
                            && proc != "(Matilda)";              // not our own send marker
                        if (isRealProc)
                        {
                            if (SendMessageA(m_appCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)proc.c_str()) == CB_ERR) {
                                SendMessageA(m_appCombo, CB_ADDSTRING, 0, (LPARAM)proc.c_str());
                                if (m_logger) {
                                    std::ostringstream ss; ss << "Added application: " << proc << "\r\n";
                                    m_logger->log(ss.str());
                                }
                            }
                        }
                    }
                }
                if (arr[i].summary) free(arr[i].summary);
            }
            delete[] arr;
        }
    }
    break;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT client; GetClientRect(hWnd, &client);

        const int topArea = 40;
        const int bottomControlsH = 100;
        int bottomTop = client.bottom - bottomControlsH;
        int rightX = m_splitPos + m_splitWidth;
        int rightW = client.right - rightX - 10;

        // Fill main background with theme window color
        HBRUSH bgBrush = CreateSolidBrush(m_theme.bgWindow);
        FillRect(hdc, &client, bgBrush);
        DeleteObject(bgBrush);

        // Helper: draw a thin-line splitter with margin.
        // The splitter rect is filled with splitterBg; a single-pixel line is drawn
        // in splitterLine colour down/across the centre.
        auto drawVSplitter = [&](int x, int w, int y1, int y2) {
            RECT r = { x, y1, x + w, y2 };
            HBRUSH b = CreateSolidBrush(m_theme.splitterBg);
            FillRect(hdc, &r, b);
            DeleteObject(b);
            int cx = x + w / 2;
            HPEN pen = CreatePen(PS_SOLID, 1, m_theme.splitterLine);
            HPEN old = (HPEN)SelectObject(hdc, pen);
            MoveToEx(hdc, cx, y1, nullptr);
            LineTo(hdc, cx, y2);
            SelectObject(hdc, old);
            DeleteObject(pen);
            };
        auto drawHSplitter = [&](int y, int h, int x1, int x2) {
            RECT r = { x1, y, x2, y + h };
            HBRUSH b = CreateSolidBrush(m_theme.splitterBg);
            FillRect(hdc, &r, b);
            DeleteObject(b);
            int cy = y + h / 2;
            HPEN pen = CreatePen(PS_SOLID, 1, m_theme.splitterLine);
            HPEN old = (HPEN)SelectObject(hdc, pen);
            MoveToEx(hdc, x1, cy, nullptr);
            LineTo(hdc, x2, cy);
            SelectObject(hdc, old);
            DeleteObject(pen);
            };

        // Vertical splitter (console | packets) — runs full height between top controls and bottom bar
        drawVSplitter(m_splitPos, m_splitWidth, topArea, bottomTop);

        // Horizontal splitter (packet list | detail) — right pane only
        drawHSplitter(m_hsplitPos, m_hsplitHeight, rightX, rightX + rightW);

        // Detail-area vertical splitter (hex | parsed panel)
        int detailTop2 = m_hsplitPos + m_hsplitHeight;
        int detailH2 = bottomTop - detailTop2;
        if (detailH2 > 0 && m_detailSplitPos > 0)
        {
            int dsX = rightX + m_detailSplitPos;
            drawVSplitter(dsX, m_detailSplitWidth, detailTop2, detailTop2 + detailH2);
        }

        EndPaint(hWnd, &ps);
    }
    break;
    case WM_SIZE:
    {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);
        RepositionControls(w, h);
    }
    break;

    case WM_NOTIFY:
    {
        NMHDR* hdr = (NMHDR*)lParam;
        if (hdr && hdr->idFrom == 9) // packet list
        {
            if (hdr->code == LVN_ITEMCHANGED)
            {
                // find selected item
                int sel = ListView_GetNextItem(m_packetList, -1, LVNI_SELECTED);
                if (sel >= 0)
                {
                    wchar_t idbuf[64] = { 0 };
                    ListView_GetItemText(m_packetList, sel, 0, idbuf, _countof(idbuf));
                    int pktIdx = _wtoi(idbuf); // or std::stoi(idbuf)

                    // retrieve bytes
                    std::vector<uint8_t> bytes;
                    if (m_captureManager && m_captureManager->getCapturedPacketBytes((size_t)pktIdx, bytes))
                    {
                        std::ostringstream oss;
                        // Fixed layout per line (16 bytes per row):
                        //   offset : 8 chars + ": " = 10
                        //   hex    : 16 * 3 chars ("XX ") = 48
                        //   gap    : "  " = 2
                        //   ascii  : 16 chars
                        //   total  = 78 chars per line + "\r\n"
                        // The hex section is always exactly 48 chars wide (padded with spaces
                        // for short final rows) so the ASCII column is always aligned.
                        for (size_t off = 0; off < bytes.size(); off += 16)
                        {
                            // offset column
                            oss << std::setw(8) << std::setfill('0') << std::hex << off << ": ";
                            // hex column — always 48 chars (16 * "XX "), pad with "   " for missing bytes
                            for (size_t b = 0; b < 16; ++b)
                            {
                                if (off + b < bytes.size())
                                    oss << std::setw(2) << std::setfill('0') << std::hex << (int)bytes[off + b] << ' ';
                                else
                                    oss << "   "; // 3 spaces to match "XX "
                            }
                            oss << " "; // one extra separator before ASCII
                            // ascii column
                            for (size_t b = 0; b < 16; ++b)
                            {
                                if (off + b < bytes.size())
                                {
                                    uint8_t ch = bytes[off + b];
                                    oss << (char)((ch >= 32 && ch < 127) ? ch : '.');
                                }
                                else
                                    oss << ' ';
                            }
                            oss << "\r\n";
                        }
                        std::string hex = oss.str();
                        SetWindowTextA(m_packetDetail, hex.c_str());

                        // populate the parsed-fields panel
                        UpdateParsedPanel(bytes);

                        // also populate preview fields from metadata
                        std::vector<std::string> meta;
                        if (m_captureManager->getCapturedMeta((size_t)pktIdx, meta))
                        {
                            std::string proto = meta.size() > 2 ? meta[2] : "TCP";
                            std::string srcIp = meta.size() > 3 ? meta[3] : std::string();
                            std::string srcPort = meta.size() > 4 ? meta[4] : std::string();
                            std::string dstIp = meta.size() > 5 ? meta[5] : std::string();
                            std::string dstPort = meta.size() > 6 ? meta[6] : std::string();
                            if (m_previewProtoCombo) {
                                int sel = (proto == "UDP") ? 1 : 0;
                                SendMessageA(m_previewProtoCombo, CB_SETCURSEL, sel, 0);
                            }
                            if (m_previewSrcPort) SetWindowTextA(m_previewSrcPort, srcPort.c_str());
                            if (m_previewDstIp) SetWindowTextA(m_previewDstIp, dstIp.c_str());
                            if (m_previewDstPort) SetWindowTextA(m_previewDstPort, dstPort.c_str());
                        }

                        // try to extract transport payload bytes to show in preview payload box (as hex)
                        std::string payloadHex;
                        if (bytes.size() >= 14 + 20)
                        {
                            size_t ipOffset = 14;
                            uint16_t ethType = (uint16_t)((bytes[12] << 8) | bytes[13]);
                            if (ethType == 0x0800 && bytes.size() > ipOffset + 20)
                            {
                                uint8_t verIhl = bytes[ipOffset];
                                uint8_t ihl = verIhl & 0x0F;
                                size_t ipHeaderLen = (size_t)ihl * 4;
                                if (bytes.size() >= ipOffset + ipHeaderLen)
                                {
                                    uint8_t protocol = bytes[ipOffset + 9];
                                    size_t transportOffset = ipOffset + ipHeaderLen;
                                    size_t transHeaderLen = 0;
                                    if (protocol == 6 && bytes.size() >= transportOffset + 20)
                                    {
                                        uint8_t dataOffsetByte = bytes[transportOffset + 12];
                                        uint8_t tcpDataOffset = (dataOffsetByte >> 4) & 0x0F;
                                        transHeaderLen = (size_t)tcpDataOffset * 4; if (transHeaderLen < 20) transHeaderLen = 20;
                                    }
                                    else if (protocol == 17 && bytes.size() >= transportOffset + 8)
                                    {
                                        transHeaderLen = 8;
                                    }
                                    size_t payloadOffset = transportOffset + transHeaderLen;
                                    if (bytes.size() > payloadOffset)
                                    {
                                        std::ostringstream ph;
                                        for (size_t i = payloadOffset; i < bytes.size(); ++i)
                                        {
                                            ph << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
                                        }
                                        payloadHex = ph.str();
                                    }
                                }
                            }
                        }
                        if (m_previewPayload)
                        {
                            if (!payloadHex.empty()) SetWindowTextA(m_previewPayload, payloadHex.c_str());
                            else SetWindowTextA(m_previewPayload, "");
                            // default to hex mode for preview
                            if (m_previewHexCheckbox) SendMessageA(m_previewHexCheckbox, BM_SETCHECK, BST_CHECKED, 0);
                        }

                    }
                    else
                    {
                        SetWindowTextA(m_packetDetail, "");
                        m_parsedFields.clear(); m_currentBytes.clear(); m_hoveredField = -1;
                        if (m_parsedPanel) InvalidateRect(m_parsedPanel, nullptr, TRUE);
                    }
                }
                else
                {
                    SetWindowTextA(m_packetDetail, "");
                    m_parsedFields.clear(); m_currentBytes.clear(); m_hoveredField = -1;
                    if (m_parsedPanel) InvalidateRect(m_parsedPanel, nullptr, TRUE);
                }
            }
            else if (hdr->code == LVN_COLUMNCLICK)
            {
                // user clicked a column header: sort by that column (toggle on repeated clicks)
                NMLISTVIEW* nmlv = (NMLISTVIEW*)lParam;
                int col = 0;
                if (nmlv) col = nmlv->iSubItem;
                if (col < 0) col = 0;

                if (col == m_sortCol) m_sortDesc = !m_sortDesc;
                else { m_sortCol = col; m_sortDesc = false; }

                LVSortParams* sp = new LVSortParams{ m_packetList, col, m_sortDesc };
                ListView_SortItems(m_packetList, ListViewCompare, (LPARAM)sp);
                delete sp;
            }
        }
    }
    break;
    case WM_LBUTTONDOWN:
    {
        int x = LOWORD(lParam);
        int y = HIWORD(lParam);
        RECT rc; GetClientRect(hWnd, &rc);
        int rightX = m_splitPos + m_splitWidth;
        int rightW = rc.right - rightX - 10;

        const int bottomControlsHeight = 100;
        int bottomTop = rc.bottom - bottomControlsHeight;
        int detailTop = m_hsplitPos + m_hsplitHeight;
        int detailH = bottomTop - detailTop;

        // vertical (left/right pane) splitter
        if (x >= m_splitPos && x <= m_splitPos + m_splitWidth)
        {
            m_vsplitDragging = true;
            SetCapture(hWnd);
        }
        // horizontal (list / detail) splitter
        else if (x >= rightX && x <= rightX + rightW && y >= m_hsplitPos && y <= m_hsplitPos + m_hsplitHeight)
        {
            m_hsplitDragging = true;
            SetCapture(hWnd);
        }
        // detail-area vertical splitter (hex | parsed)
        else if (detailH > 0 && y >= detailTop && y < detailTop + detailH)
        {
            int dsx = rightX + m_detailSplitPos;
            if (x >= dsx && x <= dsx + m_detailSplitWidth)
            {
                m_detailSplitDragging = true;
                SetCapture(hWnd);
            }
        }
    }
    break;
    case WM_MOUSEMOVE:
    {
        int x = LOWORD(lParam);
        int y = HIWORD(lParam);
        RECT rc; GetClientRect(hWnd, &rc);
        int rightX = m_splitPos + m_splitWidth;
        int rightW = rc.right - rightX - 10;
        const int bottomControlsHeight = 100;
        int bottomTop = rc.bottom - bottomControlsHeight;
        int detailTop = m_hsplitPos + m_hsplitHeight;
        int detailH = bottomTop - detailTop;

        if (m_vsplitDragging)
        {
            int minLeft = 100;
            int maxLeft = rc.right - 300;
            if (maxLeft < minLeft) maxLeft = minLeft;
            if (x < minLeft) x = minLeft;
            if (x > maxLeft) x = maxLeft;
            m_splitPos = x;
            RepositionControls(rc.right, rc.bottom);
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (m_hsplitDragging)
        {
            int topArea = 40;
            int minY = topArea + 80;
            int maxY = bottomTop - 80 - m_hsplitHeight;
            if (y < minY) y = minY;
            if (y > maxY) y = maxY;
            m_hsplitPos = y;
            RepositionControls(rc.right, rc.bottom);
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (m_detailSplitDragging)
        {
            // x is absolute; convert to offset within right pane
            int relX = x - rightX;
            int minDS = 80;
            int maxDS = rightW - 80 - m_detailSplitWidth;
            if (maxDS < minDS) maxDS = minDS;
            if (relX < minDS) relX = minDS;
            if (relX > maxDS) relX = maxDS;
            m_detailSplitPos = relX;
            RepositionControls(rc.right, rc.bottom);
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else
        {
            // Cursor feedback
            bool onVSplit = (x >= m_splitPos && x <= m_splitPos + m_splitWidth);
            bool onHSplit = (x >= rightX && x <= rightX + rightW &&
                y >= m_hsplitPos && y <= m_hsplitPos + m_hsplitHeight);
            int dsx = rightX + m_detailSplitPos;
            bool onDSplit = (detailH > 0 && y >= detailTop && y < detailTop + detailH &&
                x >= dsx && x <= dsx + m_detailSplitWidth);
            if (onVSplit || onDSplit)
                SetCursor(LoadCursor(NULL, IDC_SIZEWE));
            else if (onHSplit)
                SetCursor(LoadCursor(NULL, IDC_SIZENS));
        }
    }
    break;
    case WM_LBUTTONUP:
    {
        if (m_vsplitDragging || m_hsplitDragging || m_detailSplitDragging)
        {
            m_vsplitDragging = false;
            m_hsplitDragging = false;
            m_detailSplitDragging = false;
            ReleaseCapture();
        }
    }
    break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

LRESULT CALLBACK MainApp::StaticWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    MainApp* pThis = nullptr;
    if (message == WM_CREATE)
    {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        pThis = (MainApp*)cs->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    }
    else
    {
        pThis = (MainApp*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }
    if (pThis)
        return pThis->HandleMessage(hWnd, message, wParam, lParam);
    return DefWindowProc(hWnd, message, wParam, lParam);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    MainApp app(hInstance);
    return app.Run(nCmdShow);
}