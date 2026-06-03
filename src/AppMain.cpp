// AppMain.cpp - main application class
#include "framework.h"
#include "resource.h"
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

#include "Utils/HexParser.h"

// ---------------------------------------------------------------------------
// Packet field parser — Ethernet / IPv4 / TCP / UDP
// ---------------------------------------------------------------------------
/*static*/
std::vector<ParsedField> MainApp::ParsePacketFields(const std::vector<uint8_t>& b)
{
	std::vector<ParsedField> fields;
	if (b.size() < 14) return fields;

	auto addField = [&](const char* layer, const char* name, size_t off, size_t len, const std::string& val) {
		ParsedField f; f.layerTag = layer; f.name = name;
		f.byteOffset = off; f.byteLen = len; f.value = val;
		fields.push_back(f);
		};
	auto u8 = [&](size_t o) -> uint8_t { return b[o]; };
	auto u16 = [&](size_t o) -> uint16_t { return (uint16_t)((b[o] << 8) | b[o + 1]); };
	auto u32 = [&](size_t o) -> uint32_t {
		return ((uint32_t)b[o] << 24) | ((uint32_t)b[o + 1] << 16) | ((uint32_t)b[o + 2] << 8) | b[o + 3];
		};
	auto hex2 = [&](size_t o) { char buf[8]; snprintf(buf, sizeof(buf), "%02X", b[o]); return std::string(buf); };
	auto mac = [&](size_t o) {
		char buf[24];
		snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5]);
		return std::string(buf);
		};
	auto ip4 = [&](size_t o) {
		char buf[24]; snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[o], b[o + 1], b[o + 2], b[o + 3]); return std::string(buf);
		};
	auto dec16 = [](uint16_t v) { return std::to_string(v); };
	auto dec32 = [](uint32_t v) { return std::to_string(v); };

	// Ethernet
	addField("ETH", "Dst MAC", 0, 6, mac(0));
	addField("ETH", "Src MAC", 6, 6, mac(6));
	uint16_t ethType = u16(12);
	{ char buf[32]; snprintf(buf, sizeof(buf), "0x%04X", ethType); addField("ETH", "EtherType", 12, 2, buf); }

	if (ethType != 0x0800 || b.size() < 14 + 20) return fields;

	// IPv4
	size_t ip = 14;
	uint8_t verIhl = u8(ip);
	addField("IP", "Version", ip + 0, 1, std::to_string((verIhl >> 4) & 0xF));
	addField("IP", "IHL (words)", ip + 0, 1, std::to_string(verIhl & 0xF));
	addField("IP", "DSCP/ECN", ip + 1, 1, hex2(ip + 1));
	addField("IP", "Total Len", ip + 2, 2, dec16(u16(ip + 2)));
	addField("IP", "ID", ip + 4, 2, [&] {char b2[16]; snprintf(b2, sizeof(b2), "0x%04X", u16(ip + 4)); return std::string(b2); }());
	uint16_t frag = u16(ip + 6);
	{ char buf[48]; snprintf(buf, sizeof(buf), "0x%04X (DF=%d MF=%d off=%d)", frag, (frag >> 14) & 1, (frag >> 13) & 1, frag & 0x1FFF); addField("IP", "Flags/Fragment", ip + 6, 2, buf); }
	addField("IP", "TTL", ip + 8, 1, dec16(u8(ip + 8)));
	uint8_t proto = u8(ip + 9);
	{ std::string ps = std::to_string(proto); if (proto == 6)ps += " (TCP)"; else if (proto == 17)ps += " (UDP)"; else if (proto == 1)ps += " (ICMP)"; addField("IP", "Protocol", ip + 9, 1, ps); }
	{ char buf[16]; snprintf(buf, sizeof(buf), "0x%04X", u16(ip + 10)); addField("IP", "Header Checksum", ip + 10, 2, buf); }
	addField("IP", "Src IP", ip + 12, 4, ip4(ip + 12));
	addField("IP", "Dst IP", ip + 16, 4, ip4(ip + 16));

	size_t ihl = (size_t)(verIhl & 0x0F) * 4; if (ihl < 20)ihl = 20;
	if (b.size() < ip + ihl) return fields;
	size_t tp = ip + ihl;

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
		size_t tcpHdrLen = (size_t)dataOff * 4; if (tcpHdrLen < 20)tcpHdrLen = 20;
		size_t payOff = tp + tcpHdrLen;
		if (payOff < b.size()) addField("TCP", "Payload", payOff, b.size() - payOff, "[" + std::to_string(b.size() - payOff) + " bytes]");
	}
	else if (proto == 17 && b.size() >= tp + 8)
	{
		addField("UDP", "Src Port", tp + 0, 2, dec16(u16(tp + 0)));
		addField("UDP", "Dst Port", tp + 2, 2, dec16(u16(tp + 2)));
		addField("UDP", "Length", tp + 4, 2, dec16(u16(tp + 4)));
		{ char buf[16]; snprintf(buf, sizeof(buf), "0x%04X", u16(tp + 6)); addField("UDP", "Checksum", tp + 6, 2, buf); }
		if (b.size() > tp + 8) addField("UDP", "Payload", tp + 8, b.size() - (tp + 8), "[" + std::to_string(b.size() - (tp + 8)) + " bytes]");
	}
	return fields;
}

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
	HBRUSH bgBrush = CreateSolidBrush(m_theme.bgWindow);
	FillRect(hdc, &rc, bgBrush);
	DeleteObject(bgBrush);

	if (m_parsedFields.empty())
	{
		SetTextColor(hdc, m_theme.textColor);
		SetBkMode(hdc, TRANSPARENT);
		const char* msg = "No packet selected";
		TextOutA(hdc, rc.left + 8, rc.top + 8, msg, (int)strlen(msg));
		return;
	}

	HFONT monoFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
	HFONT hdrFont = CreateFontA(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

	int colSplit = rc.left + (rc.right - rc.left) * 42 / 100;
	int rowH = PARSED_ROW_H;
	int y = rc.top - GetScrollPos(m_parsedPanel, SB_VERT) * rowH;

	std::string lastLayer;
	int rowIndex = 0;

	for (int fi = 0; fi < (int)m_parsedFields.size(); ++fi)
	{
		const ParsedField& f = m_parsedFields[fi];
		bool               collapsed = (m_collapsedLayers.count(f.layerTag) > 0);

		if (f.layerTag != lastLayer)
		{
			lastLayer = f.layerTag;
			if (y + rowH > rc.top && y < rc.bottom)
			{
				RECT headerRect = { rc.left, y, rc.right, y + rowH };
				// Use tinted variants of the theme splitterBg for layer headers
				auto brighten = [&](COLORREF c, int d) {
					return RGB(min(255, (int)GetRValue(c) + d), min(255, (int)GetGValue(c) + d), min(255, (int)GetBValue(c) + d));
				};
				COLORREF hdrColor =
					(f.layerTag == "ETH") ? brighten(m_theme.splitterBg, 30) :
					(f.layerTag == "IP") ? brighten(m_theme.splitterBg, 20) :
					(f.layerTag == "TCP") ? brighten(m_theme.splitterBg, 10) :
					(f.layerTag == "UDP") ? brighten(m_theme.splitterBg, 15) :
					brighten(m_theme.splitterBg, 8);
				HBRUSH hdrBrush = CreateSolidBrush(hdrColor);
				FillRect(hdc, &headerRect, hdrBrush);
				DeleteObject(hdrBrush);
				SelectObject(hdc, hdrFont);
				SetTextColor(hdc, m_theme.textColor);
				SetBkMode(hdc, TRANSPARENT);
				std::string hdrText = std::string(collapsed ? "> " : "v ") + f.layerTag;
				TextOutA(hdc, rc.left + 4, y + 2, hdrText.c_str(), (int)hdrText.size());
				HPEN pen = CreatePen(PS_SOLID, 1, RGB(180, 180, 190));
				HPEN old = (HPEN)SelectObject(hdc, pen);
				MoveToEx(hdc, rc.left, y + rowH - 1, nullptr); LineTo(hdc, rc.right, y + rowH - 1);
				SelectObject(hdc, old); DeleteObject(pen);
			}
			y += rowH; rowIndex++;
		}

		if (collapsed) continue;
		if (y + rowH <= rc.top) { y += rowH; rowIndex++; continue; }
		if (y >= rc.bottom) break;

		RECT rowRect = { rc.left, y, rc.right, y + rowH };
		bool hovered = (fi == m_hoveredField);
		COLORREF rowBg = hovered
			? RGB(198, 220, 255)
			: (rowIndex % 2 == 0 ? m_theme.bgWindow
				: RGB(
					min(255, (int)GetRValue(m_theme.bgWindow) + 8),
					min(255, (int)GetGValue(m_theme.bgWindow) + 8),
					min(255, (int)GetBValue(m_theme.bgWindow) + 8)));
		HBRUSH rowBrush = CreateSolidBrush(rowBg);
		FillRect(hdc, &rowRect, rowBrush);
		DeleteObject(rowBrush);

		HPEN divPen = CreatePen(PS_SOLID, 1, m_theme.splitterLine);
		HPEN oldPen = (HPEN)SelectObject(hdc, divPen);
		MoveToEx(hdc, colSplit, y, nullptr); LineTo(hdc, colSplit, y + rowH);
		SelectObject(hdc, oldPen); DeleteObject(divPen);

		HPEN borderPen = CreatePen(PS_SOLID, 1, m_theme.splitterBg);
		oldPen = (HPEN)SelectObject(hdc, borderPen);
		MoveToEx(hdc, rc.left, y + rowH - 1, nullptr); LineTo(hdc, rc.right, y + rowH - 1);
		SelectObject(hdc, oldPen); DeleteObject(borderPen);

		SelectObject(hdc, monoFont);
		SetBkMode(hdc, TRANSPARENT);

		SetTextColor(hdc, hovered ? RGB(0, 50, 150) : m_theme.textColor);
		RECT nameRect = { rc.left + 6, y + 1, colSplit - 2, y + rowH };
		DrawTextA(hdc, f.name.c_str(), -1, &nameRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

		SetTextColor(hdc, hovered ? RGB(0, 100, 0) : m_theme.textColor);
		RECT valRect = { colSplit + 4, y + 1, rc.right - 2, y + rowH };
		DrawTextA(hdc, f.value.c_str(), -1, &valRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

		y += rowH; rowIndex++;
	}

	DeleteObject(monoFont);
	DeleteObject(hdrFont);
}

// ---------------------------------------------------------------------------
// Highlight hex bytes corresponding to a parsed field
//
// Fixed layout per row (16 bytes):
//   offset col : "XXXXXXXX: "  = 10 chars
//   hex col    : "XX " * 16    = 48 chars  (last entry has no trailing space but we pad)
//   sep        : "  "          =  2 chars
//   ascii col  : 16 chars
//   line end   : "\r\n"        =  2 chars
//   total      : 62 chars      (lineLen below — must match the layout in WM_NOTIFY)
// ---------------------------------------------------------------------------
void MainApp::HighlightHexRange(size_t byteOffset, size_t byteLen)
{
	if (!m_packetDetail || m_currentBytes.empty()) return;

	// Must match the layout written in WM_NOTIFY / LVN_ITEMCHANGED
	const int kBytesPerLine = 16;
	const int kOffsetLen = 10;  // "XXXXXXXX: "
	const int kHexLen = 48;  // 16 * "XX " (each 3 chars)
	const int kSepLen = 2;   // "  "
	const int kAsciiLen = 16;
	const int kLineEnd = 2;   // "\r\n"
	const int kLineLen = kOffsetLen + kHexLen + kSepLen + kAsciiLen + kLineEnd; // 78

	auto byteToHexChar = [&](size_t b) -> int {
		int line = (int)(b / kBytesPerLine);
		int col = (int)(b % kBytesPerLine);
		return line * kLineLen + kOffsetLen + col * 3; // "XX " = 3 chars
		};

	if (byteLen == 0) return;
	int selStart = byteToHexChar(byteOffset);
	int selEnd = byteToHexChar(byteOffset + byteLen - 1) + 2; // 2 hex digits

	SendMessageA(m_packetDetail, EM_SETSEL, (WPARAM)selStart, (LPARAM)selEnd);
	SendMessageA(m_packetDetail, EM_SCROLLCARET, 0, 0);
}

// ---------------------------------------------------------------------------
// Apply current theme to all child controls
// ---------------------------------------------------------------------------
void MainApp::ApplyTheme()
{
	if (!m_mainWindow) return;

	// Main window background (class brush)
	SetClassLongPtr(m_mainWindow, GCLP_HBRBACKGROUND,
		(LONG_PTR)CreateSolidBrush(m_theme.bgWindow));

	// Create or update application UI font (Segoe UI, normal weight)
	static HFONT s_uiFont = nullptr;
	if (s_uiFont) DeleteObject(s_uiFont);
	s_uiFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

	// Apply the font to common child controls
	auto applyFont = [&](HWND h) { if (h) SendMessage(h, WM_SETFONT, (WPARAM)s_uiFont, TRUE); };
	applyFont(m_outputBox);
	applyFont(m_packetDetail);
	applyFont(m_packetList);
	applyFont(m_parsedPanel);
	applyFont(m_deviceCombo);
	applyFont(m_appCombo);
	applyFont(m_previewProtoCombo);
	applyFont(m_previewSrcPort);
	applyFont(m_previewDstIp);
	applyFont(m_previewDstPort);
	applyFont(m_previewPayload);

	// ListView (packet table) background and text colors
	if (m_packetList) {
		ListView_SetBkColor(m_packetList, m_theme.tableBg);
		ListView_SetTextColor(m_packetList, m_theme.textColor);
	}

	// Ensure common controls repaint to pick up new colors and brushes handled by WM_CTLCOLOR*
	InvalidateRect(m_mainWindow, nullptr, TRUE);
	UpdateWindow(m_mainWindow);

	// Force EDIT/COMBOBOX/OTHER controls to repaint immediately with new colors
	auto repaint = [](HWND h) { if (h) { InvalidateRect(h, nullptr, TRUE); UpdateWindow(h); } };
	repaint(m_outputBox);
	repaint(m_packetDetail);
	repaint(m_packetList);
	repaint(m_parsedPanel);
	repaint(m_deviceCombo);
	repaint(m_appCombo);
}

// ---------------------------------------------------------------------------
// Parsed panel window proc — static trampoline
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
		pThis = (MainApp*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

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
		PAINTSTRUCT ps; HDC hdc = BeginPaint(hWnd, &ps);
		RECT rc; GetClientRect(hWnd, &rc);
		PaintParsedPanel(hdc, rc);
		EndPaint(hWnd, &ps);
		return 0;
	}
	case WM_ERASEBKGND: return 1;

	case WM_MOUSEMOVE:
	{
		TRACKMOUSEEVENT tme{}; tme.cbSize = sizeof(tme); tme.dwFlags = TME_LEAVE; tme.hwndTrack = hWnd;
		TrackMouseEvent(&tme);

		int scrollY = GetScrollPos(hWnd, SB_VERT);
		int rowH = PARSED_ROW_H;
		int y = -scrollY * rowH;
		int my = GET_Y_LPARAM(lParam);
		std::string lastLayer;
		int hitField = -1;
		for (int fi = 0; fi < (int)m_parsedFields.size(); ++fi)
		{
			const ParsedField& f = m_parsedFields[fi];
			bool               coll = (m_collapsedLayers.count(f.layerTag) > 0);
			if (f.layerTag != lastLayer) { lastLayer = f.layerTag; y += rowH; }
			if (coll) continue;
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
		}
		return 0;
	}
	case WM_LBUTTONDOWN:
	{
		int my = GET_Y_LPARAM(lParam);
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
				if (my >= y && my < y + rowH)
				{
					if (m_collapsedLayers.count(f.layerTag)) m_collapsedLayers.erase(f.layerTag);
					else                                      m_collapsedLayers.insert(f.layerTag);
					m_hoveredField = -1;
					InvalidateRect(hWnd, nullptr, TRUE);
					return 0;
				}
				y += rowH;
			}
			if (!m_collapsedLayers.count(f.layerTag)) y += rowH;
		}
		return 0;
	}
	case WM_MOUSELEAVE:
		if (m_hoveredField != -1) { m_hoveredField = -1; InvalidateRect(hWnd, nullptr, TRUE); }
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
	case WM_SIZE: InvalidateRect(hWnd, nullptr, TRUE); return 0;

	case WM_VSCROLL:
	{
		SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_ALL;
		GetScrollInfo(hWnd, SB_VERT, &si);
		int np = si.nPos;
		switch (LOWORD(wParam)) {
		case SB_TOP:        np = si.nMin; break;
		case SB_BOTTOM:     np = si.nMax; break;
		case SB_LINEUP:     np--; break;
		case SB_LINEDOWN:   np++; break;
		case SB_PAGEUP:     np -= si.nPage; break;
		case SB_PAGEDOWN:   np += si.nPage; break;
		case SB_THUMBTRACK: np = si.nTrackPos; break;
		}
		if (np < si.nMin)np = si.nMin;
		if (np > (int)(si.nMax - (int)si.nPage + 1))np = si.nMax - (int)si.nPage + 1;
		si.fMask = SIF_POS; si.nPos = np;
		SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
		InvalidateRect(hWnd, nullptr, TRUE);
		return 0;
	}
	case WM_MOUSEWHEEL:
	{
		int delta = GET_WHEEL_DELTA_WPARAM(wParam) / WHEEL_DELTA;
		SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_ALL;
		GetScrollInfo(hWnd, SB_VERT, &si);
		int np = si.nPos - delta;
		if (np < si.nMin)np = si.nMin;
		if (np > (int)(si.nMax - (int)si.nPage + 1))np = si.nMax - (int)si.nPage + 1;
		si.fMask = SIF_POS; si.nPos = np;
		SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
		InvalidateRect(hWnd, nullptr, TRUE);
		return 0;
	}
	}
	return DefWindowProcA(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
void MainApp::PopulateProcessCombo(HWND combo)
{
	if (!combo) return;
	std::unordered_set<std::string> seen;
	DWORD aProcesses[1024]{}; DWORD cbNeeded = 0;
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return;
	DWORD count = cbNeeded / sizeof(DWORD);
	for (DWORD i = 0; i < count; ++i)
	{
		DWORD pid = aProcesses[i]; if (!pid) continue;
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!h) continue;
		char buf[MAX_PATH]; DWORD sz = MAX_PATH;
		if (QueryFullProcessImageNameA(h, 0, buf, &sz))
		{
			const char* p = strrchr(buf, '\\');
			const char* name = p ? p + 1 : buf;
			if (name && name[0])
			{
				std::string sname = name;
				if (sname == "All Applications" || seen.count(sname)) { CloseHandle(h); continue; }
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
	LVCOLUMNA col{}; col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	auto addCol = [&](const char* txt, int w, int i) {
		col.pszText = (LPSTR)txt; col.cx = w;
		SendMessageA(m_packetList, LVM_INSERTCOLUMNA, i, (LPARAM)&col);
		};
	addCol("ID", 50, 0); addCol("TIME", 120, 1); addCol("DIR", 60, 2); addCol("PROTO", 60, 3);
	addCol("SRC", 140, 4); addCol("S PORT", 60, 5); addCol("DST", 140, 6); addCol("D PORT", 60, 7);
	addCol("LEN", 60, 8); addCol("PROC", 140, 9);
	ListView_SetExtendedListViewStyle(m_packetList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

struct LVSortParams { HWND hwnd; int col; bool desc; };

static int CALLBACK ListViewCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	LVSortParams* p = (LVSortParams*)lParamSort;
	if (!p || !p->hwnd) return 0;
	LVFINDINFO fi{}; fi.flags = LVFI_PARAM;
	fi.lParam = lParam1; int idx1 = ListView_FindItem(p->hwnd, -1, &fi);
	fi.lParam = lParam2; int idx2 = ListView_FindItem(p->hwnd, -1, &fi);
	wchar_t buf1[512] = {}, buf2[512] = {};
	if (idx1 != -1) ListView_GetItemText(p->hwnd, idx1, p->col, buf1, _countof(buf1));
	if (idx2 != -1) ListView_GetItemText(p->hwnd, idx2, p->col, buf2, _countof(buf2));
	int cmp = 0;
	if (p->col == 0 || p->col == 5 || p->col == 7 || p->col == 8) {
		long v1 = 0, v2 = 0;
		try { v1 = std::stol(buf1); }
		catch (...) {}
		try { v2 = std::stol(buf2); }
		catch (...) {}
		cmp = (v1 < v2) ? -1 : (v1 > v2) ? 1 : 0;
	}
	else cmp = _wcsicmp(buf1, buf2);
	if (p->desc) cmp = -cmp;
	return cmp;
}

void MainApp::RepositionControls(int clientW, int clientH)
{
	const int margin = 10;
	const int topArea = 40;
	const int bottomControlsHeight = 100;

	if (m_splitPos <= 0) m_splitPos = margin + 200;
	{ int mn = 100, mx = clientW - 300; if (mx < mn)mx = mn; if (m_splitPos < mn)m_splitPos = mn; if (m_splitPos > mx)m_splitPos = mx; }

	int leftX = margin;
	int leftW = m_splitPos - margin;
	int rightX = m_splitPos + m_splitWidth;
	int rightW = clientW - rightX - margin;

	int listTop = topArea;
	int bottomTop = clientH - bottomControlsHeight;
	int availH = bottomTop - listTop; if (availH < 140)availH = 140;

	if (m_hsplitPos <= 0) m_hsplitPos = listTop + availH * 70 / 100;
	{ int mn = listTop + 80, mx = listTop + availH - 80 - m_hsplitHeight; if (mx < mn)mx = mn; if (m_hsplitPos < mn)m_hsplitPos = mn; if (m_hsplitPos > mx)m_hsplitPos = mx; }

	int listH = m_hsplitPos - listTop; if (listH < 80)listH = 80;
	int detailH = availH - listH - m_hsplitHeight; if (detailH < 60)detailH = 60;

	if (m_outputBox)    MoveWindow(m_outputBox, leftX, listTop, leftW, bottomTop - listTop, TRUE);
	if (m_packetList)   MoveWindow(m_packetList, rightX, listTop, rightW, listH, TRUE);

	int detailTop = listTop + listH + m_hsplitHeight;
	{ int mn = 80, mx = rightW - 80 - m_detailSplitWidth; if (mx < mn)mx = mn; if (m_detailSplitPos <= 0)m_detailSplitPos = rightW / 2; if (m_detailSplitPos < mn)m_detailSplitPos = mn; if (m_detailSplitPos > mx)m_detailSplitPos = mx; }

	int hexW = m_detailSplitPos;
	int parsedX = rightX + m_detailSplitPos + m_detailSplitWidth;
	int parsedW = rightW - m_detailSplitPos - m_detailSplitWidth; if (parsedW < 60)parsedW = 60;

	if (m_packetDetail) MoveWindow(m_packetDetail, rightX, detailTop, hexW, detailH, TRUE);
	if (m_parsedPanel)
	{
		MoveWindow(m_parsedPanel, parsedX, detailTop, parsedW, detailH, TRUE);
		int totalRows = 0; std::string ll;
		for (auto& f : m_parsedFields) { if (f.layerTag != ll) { ll = f.layerTag; totalRows++; } totalRows++; }
		int visRows = detailH / PARSED_ROW_H;
		SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_RANGE | SIF_PAGE;
		si.nMin = 0; si.nMax = (totalRows > 0) ? totalRows - 1 : 0; si.nPage = (visRows > 0) ? visRows : 1;
		SetScrollInfo(m_parsedPanel, SB_VERT, &si, TRUE);
	}

	// Top controls
	if (m_appCombo)    MoveWindow(m_appCombo, leftX, 10, leftW, 24, TRUE);
	if (m_deviceCombo) { int dcW = rightW - 120; if (dcW < 120)dcW = 120; MoveWindow(m_deviceCombo, rightX, 10, dcW, 24, TRUE); }
	HWND btnStart = GetDlgItem(m_mainWindow, 1);
	if (btnStart) MoveWindow(btnStart, clientW - 110 - margin, 10, 100, 24, TRUE);

	// Bottom row 1: [Replay Last] | [proto][srcPort][dstIp][dstPort][payload] | [Send Custom]
	const int btnReplayW = 100, btnSendW = 130;
	const int row1Y = bottomTop + 8;
	HWND btnReplay = GetDlgItem(m_mainWindow, 4);
	if (btnReplay) MoveWindow(btnReplay, leftX, row1Y, btnReplayW, 24, TRUE);
	HWND btnSend = GetDlgItem(m_mainWindow, 6);
	if (btnSend) MoveWindow(btnSend, clientW - btnSendW - margin, row1Y, btnSendW, 24, TRUE);

	{
		int previewX = leftX + btnReplayW + 6;
		int previewEnd = clientW - btnSendW - margin - 6;
		int totalW = previewEnd - previewX; if (totalW < 100)totalW = 100;
		const int wProto = 72, wSrcPort = 58, wDstIp = 120, wDstPort = 58, gaps = 12;
		int wPayload = totalW - wProto - wSrcPort - wDstIp - wDstPort - gaps;
		if (wPayload < 60)wPayload = 60;
		int cx = previewX;
		if (m_previewProtoCombo) { MoveWindow(m_previewProtoCombo, cx, row1Y, wProto, 24, TRUE); cx += wProto + 4; }
		if (m_previewSrcPort) { MoveWindow(m_previewSrcPort, cx, row1Y, wSrcPort, 24, TRUE); cx += wSrcPort + 4; }
		if (m_previewDstIp) { MoveWindow(m_previewDstIp, cx, row1Y, wDstIp, 24, TRUE); cx += wDstIp + 4; }
		if (m_previewDstPort) { MoveWindow(m_previewDstPort, cx, row1Y, wDstPort, 24, TRUE); cx += wDstPort + 4; }
		if (m_previewPayload) { MoveWindow(m_previewPayload, cx, row1Y, wPayload, 24, TRUE); }
	}

	HWND btnFilter = GetDlgItem(m_mainWindow, 8);
	if (btnFilter) MoveWindow(btnFilter, leftX, bottomTop + 40, 120, 24, TRUE);
}

void MainApp::PopulateDeviceList()
{
	if (!m_captureManager || !m_deviceCombo) return;
	auto devs = m_captureManager->getDeviceList();
	for (const auto& d : devs) SendMessageA(m_deviceCombo, CB_ADDSTRING, 0, (LPARAM)d.c_str());
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
	if (sel == CB_ERR)sel = 0;
	m_captureManager->start([this](const std::string& s, int) { if (m_logger)m_logger->log(s); },
		sel, m_mainWindow);
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
	, m_outputBox(nullptr), m_mainWindow(nullptr)
	, m_deviceCombo(nullptr), m_appCombo(nullptr)
	, m_packetList(nullptr), m_packetDetail(nullptr)
	, m_previewProtoCombo(nullptr), m_previewSrcPort(nullptr)
	, m_previewDstIp(nullptr), m_previewDstPort(nullptr), m_previewPayload(nullptr)
	, m_splitPos(0), m_splitWidth(8), m_vsplitDragging(false)
	, m_hsplitPos(0), m_hsplitHeight(6), m_hsplitDragging(false)
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
	wcex.hInstance = hInst;
	wcex.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_MATILDA));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = nullptr;
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
	RegisterClassExW(&wcex);

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, 800, 600, nullptr, nullptr, hInst, this);
	m_mainWindow = hWnd;

	// Menu: Settings > Theme > White / Dark
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

	const int margin = 10, topArea = 40;
	const int initialW = 800, leftW = 200;
	const int rightX = margin + leftW + margin, rightW = initialW - rightX - margin;

	m_outputBox = CreateWindowA("EDIT", "",
		WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
		margin, topArea, leftW, 420, hWnd, nullptr, hInst, nullptr);

	m_splitPos = margin + leftW; m_splitWidth = 8; m_vsplitDragging = false;
	m_hsplitHeight = 6; m_hsplitPos = topArea + 360; m_hsplitDragging = false;

	m_packetList = CreateWindowExA(0, WC_LISTVIEWA, "",
		WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | WS_VSCROLL,
		rightX, topArea, rightW, 360, hWnd, (HMENU)9, hInst, nullptr);

	// Preview controls (bottom toolbar)
	m_previewProtoCombo = CreateWindowExA(WS_EX_CLIENTEDGE, "COMBOBOX", "",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
		0, 0, 80, 200, hWnd, (HMENU)12, hInst, nullptr);
	if (m_previewProtoCombo) {
		SendMessageA(m_previewProtoCombo, CB_ADDSTRING, 0, (LPARAM)"TCP");
		SendMessageA(m_previewProtoCombo, CB_ADDSTRING, 0, (LPARAM)"UDP");
		SendMessageA(m_previewProtoCombo, CB_SETCURSEL, 0, 0);
	}
	m_previewSrcPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 60, 24, hWnd, (HMENU)13, hInst, nullptr);
	m_previewDstIp = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 130, 24, hWnd, (HMENU)14, hInst, nullptr);
	m_previewDstPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 60, 24, hWnd, (HMENU)15, hInst, nullptr);
	m_previewPayload = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 160, 24, hWnd, (HMENU)16, hInst, nullptr);
	// m_previewHexCheckbox intentionally omitted — payload is always treated as hex

	m_packetDetail = CreateWindowA("EDIT", "",
		WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL | WS_HSCROLL | ES_AUTOHSCROLL,
		rightX, topArea + 360, rightW / 2, 120, hWnd, (HMENU)10, hInst, nullptr);

	// Register custom class for parsed-fields panel
	{
		WNDCLASSEXA wc{}; wc.cbSize = sizeof(wc); wc.style = CS_HREDRAW | CS_VREDRAW;
		wc.lpfnWndProc = MainApp::StaticParsedPanelProc; wc.hInstance = hInst;
		wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = nullptr;
		wc.lpszClassName = "MatildaParsedPanel";
		RegisterClassExA(&wc);
	}
	m_parsedPanel = CreateWindowExA(WS_EX_CLIENTEDGE, "MatildaParsedPanel", "",
		WS_CHILD | WS_VISIBLE | WS_VSCROLL,
		rightX + rightW / 2 + m_detailSplitWidth, topArea + 360, rightW / 2, 120,
		hWnd, (HMENU)18, hInst, this);

	// Tooltip for parsed panel
	m_parsedTooltip = CreateWindowEx(0, TOOLTIPS_CLASS, nullptr,
		WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		m_parsedPanel, nullptr, hInst, nullptr);
	if (m_parsedTooltip) {
		SendMessage(m_parsedTooltip, TTM_SETMAXTIPWIDTH, 0, 400);
		TOOLINFO ti{}; ti.cbSize = sizeof(TOOLINFO);
		ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND; ti.hwnd = m_parsedPanel;
		ti.uId = (UINT_PTR)m_parsedPanel; ti.lpszText = LPSTR_TEXTCALLBACK;
		RECT rc; GetClientRect(m_parsedPanel, &rc); ti.rect = rc;
		SendMessage(m_parsedTooltip, TTM_ADDTOOLA, 0, (LPARAM)&ti);
	}

	m_detailSplitPos = rightW / 2; m_detailSplitWidth = 6; m_detailSplitDragging = false;

	m_appCombo = CreateWindowA("COMBOBOX", "All Applications",
		WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
		margin, 10, leftW, 200, hWnd, (HMENU)11, hInst, nullptr);

	int dcW = rightW - 120; if (dcW < 120)dcW = 120;
	m_deviceCombo = CreateWindowA("COMBOBOX", "",
		WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
		rightX, 10, dcW, 200, hWnd, (HMENU)3, hInst, nullptr);

	CreateWindowA("BUTTON", "Start capture", WS_CHILD | WS_VISIBLE,
		initialW - 110, 10, 100, 24, hWnd, (HMENU)1, hInst, nullptr);
	CreateWindowA("BUTTON", "Replay Last", WS_CHILD | WS_VISIBLE,
		10, 470, 100, 24, hWnd, (HMENU)4, hInst, nullptr);
	CreateWindowA("BUTTON", "Send Custom", WS_CHILD | WS_VISIBLE,
		650, 470, 140, 24, hWnd, (HMENU)6, hInst, nullptr);
	CreateWindowA("BUTTON", "Apply Filter", WS_CHILD | WS_VISIBLE,
		10, 500, 120, 24, hWnd, (HMENU)8, hInst, nullptr);

	if (!hWnd) return FALSE;
	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);
	SetFocus(m_outputBox);

	m_logger.reset(new Logger(hWnd, m_outputBox));
	m_captureManager.reset(new CaptureManager());

	PopulateDeviceList();
	{
		auto devs = m_captureManager->getDeviceList();
		std::ostringstream s; s << "Found " << devs.size() << " capture devices\r\n";
		m_logger->log(s.str());
	}
	m_logger->log("Application started\r\n");

	INITCOMMONCONTROLSEX icc{}; icc.dwSize = sizeof(icc);
	icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
	InitCommonControlsEx(&icc);

	SetupListViewColumns();
	RECT rc; GetClientRect(hWnd, &rc);
	RepositionControls(rc.right, rc.bottom);

	if (m_appCombo) {
		SendMessageA(m_appCombo, CB_ADDSTRING, 0, (LPARAM)"All Applications");
		SendMessageA(m_appCombo, CB_SETCURSEL, 0, 0);
	}

	MSG msg;
	while (GetMessage(&msg, nullptr, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}

// ---------------------------------------------------------------------------
// Main window message handler
// ---------------------------------------------------------------------------
LRESULT MainApp::HandleMessage(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		// ------------------------------------------------------------------
		// Theme menu commands
		// ------------------------------------------------------------------
	case WM_COMMAND:
	{
		int cmdId = LOWORD(wParam);

		if (cmdId == IDM_THEME_WHITE)
		{
			m_theme = Themes::White();
			ApplyTheme();
			return 0;
		}
		if (cmdId == IDM_THEME_DARK)
		{
			m_theme = Themes::Dark();
			ApplyTheme();
			return 0;
		}

		if (cmdId == 1)
		{
			if (m_capturing) OnStopCapture(); else OnStartCapture();
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
			// Send Custom — requires active capture
			if (!m_captureManager) break;
			if (!m_captureManager->isRunning())
			{
				if (m_logger) m_logger->log("Cannot send: capture is not running\r\n");
				break;
			}

			int selRow = ListView_GetNextItem(m_packetList, -1, LVNI_SELECTED);
			if (selRow < 0) break;

			wchar_t idbuf[64] = {};
			ListView_GetItemText(m_packetList, selRow, 0, idbuf, _countof(idbuf));
			int pktIdx = _wtoi(idbuf);

			char protoBuf[32] = {}, srcPortBuf[32] = {}, dstIpBuf[64] = {},
				dstPortBuf[32] = {}, payloadBuf[8192] = {};
			if (m_previewProtoCombo) { int ps = (int)SendMessageA(m_previewProtoCombo, CB_GETCURSEL, 0, 0); if (ps != CB_ERR) SendMessageA(m_previewProtoCombo, CB_GETLBTEXT, ps, (LPARAM)protoBuf); }
			if (m_previewSrcPort)   GetWindowTextA(m_previewSrcPort, srcPortBuf, sizeof(srcPortBuf));
			if (m_previewDstIp)     GetWindowTextA(m_previewDstIp, dstIpBuf, sizeof(dstIpBuf));
			if (m_previewDstPort)   GetWindowTextA(m_previewDstPort, dstPortBuf, sizeof(dstPortBuf));
			if (m_previewPayload)   GetWindowTextA(m_previewPayload, payloadBuf, sizeof(payloadBuf));

			std::string protoStr = protoBuf, srcPortStr = srcPortBuf;
			std::string dstIpStr = dstIpBuf, dstPortStr = dstPortBuf;
			std::string payloadStr = payloadBuf;

			// Payload is always interpreted as hex
			std::vector<uint8_t> payloadBytes;
			if (!payloadStr.empty())
			{
				if (!parseHexString(payloadStr, payloadBytes))
				{
					if (m_logger) m_logger->log("Invalid hex payload\r\n");
					break;
				}
			}

			uint16_t srcPortOverride = 0, dstPortOverride = 0;
			try { srcPortOverride = (uint16_t)std::stoi(srcPortStr); }
			catch (...) {}
			try { dstPortOverride = (uint16_t)std::stoi(dstPortStr); }
			catch (...) {}

			std::string err;
			bool ok = m_captureManager->sendCapturedPacketWithPayload(
				(size_t)pktIdx, payloadBytes, protoStr,
				std::string(), srcPortOverride, dstIpStr, dstPortOverride, &err);

			if (ok)
			{
				size_t newId = m_captureManager->getCapturedCount();
				if (newId > 0) newId--;
				if (m_logger)
				{
					std::ostringstream ss; ss << "Packet " << newId << " sent\r\n";
					m_logger->log(ss.str());
				}
			}
			else
			{
				if (m_logger)
				{
					std::ostringstream ss; ss << "Failed to send packet: " << err << "\r\n";
					m_logger->log(ss.str());
				}
			}
		}
		else if (cmdId == 8)
		{
			if (m_captureManager)
			{
				m_captureManager->setFilter(std::string());
				if (m_logger) m_logger->log("Capture filter cleared\r\n");
			}
		}
		else if (cmdId == 11 && HIWORD(wParam) == CBN_SELCHANGE)
		{
			char selbuf[256] = {};
			int sel = (int)SendMessageA(m_appCombo, CB_GETCURSEL, 0, 0);
			if (sel != CB_ERR) SendMessageA(m_appCombo, CB_GETLBTEXT, sel, (LPARAM)selbuf);
			std::string selStr = selbuf;
			bool showAll = selStr.empty() || selStr == "All Applications";
			if (m_packetList) ListView_DeleteAllItems(m_packetList);
			size_t cnt = m_captureManager ? m_captureManager->getCapturedCount() : 0;
			for (size_t i = 0; i < cnt; ++i) {
				std::vector<std::string> meta;
				if (!m_captureManager->getCapturedMeta(i, meta)) continue;
				std::string proc = meta.size() > 8 ? meta[8] : std::string();
				if (!showAll && proc != selStr) continue;
				int itemIndex = (int)SendMessageA(m_packetList, LVM_GETITEMCOUNT, 0, 0);
				LVITEMA it{}; it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = itemIndex; it.lParam = (LPARAM)i;
				char idbuf2[32]; snprintf(idbuf2, sizeof(idbuf2), "%d", (int)i); it.pszText = idbuf2;
				SendMessageA(m_packetList, LVM_INSERTITEMA, 0, (LPARAM)&it);
				for (int c = 0; c < (int)meta.size() && c < 9; ++c) {
					LVITEMA sub{}; sub.mask = LVIF_TEXT; sub.iItem = itemIndex; sub.iSubItem = c + 1;
					sub.pszText = const_cast<char*>(meta[c].c_str());
					SendMessageA(m_packetList, LVM_SETITEMA, 0, (LPARAM)&sub);
				}
			}
		}
	}
	break;

	// ------------------------------------------------------------------
	// Color the EDIT and COMBOBOX controls with the current theme
	// ------------------------------------------------------------------
	case WM_CTLCOLOREDIT:
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcCtrl = (HDC)wParam;
		SetTextColor(hdcCtrl, m_theme.textColor);
			SetBkColor(hdcCtrl, m_theme.dropdownBg);
			// Return a brush with the dropdown/edit background color
		static HBRUSH s_editBrush = nullptr;
		if (s_editBrush) DeleteObject(s_editBrush);
			s_editBrush = CreateSolidBrush(m_theme.dropdownBg);
		return (LRESULT)s_editBrush;
	}
	case WM_CTLCOLORLISTBOX:
	{
		HDC hdcCtrl = (HDC)wParam;
		SetTextColor(hdcCtrl, m_theme.textColor);
			SetBkColor(hdcCtrl, m_theme.dropdownBg);
		static HBRUSH s_lbBrush = nullptr;
		if (s_lbBrush) DeleteObject(s_lbBrush);
			s_lbBrush = CreateSolidBrush(m_theme.dropdownBg);
		return (LRESULT)s_lbBrush;
	}
	case WM_CTLCOLORBTN:
	{
		HDC hdcCtrl = (HDC)wParam;
		SetTextColor(hdcCtrl, m_theme.textColor);
			SetBkColor(hdcCtrl, m_theme.bgButton);
		static HBRUSH s_btnBrush = nullptr;
		if (s_btnBrush) DeleteObject(s_btnBrush);
			s_btnBrush = CreateSolidBrush(m_theme.bgButton);
		return (LRESULT)s_btnBrush;
	}

	case WM_APP + 1:
	{
		std::string* text = (std::string*)lParam;
		if (text) { AppendText(*text); delete text; }
	}
	break;

	case WM_APP + 2:
	{
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
					std::vector<std::string> cols;
					std::string s(summary);
					size_t pos = 0;
					while (true) {
						size_t tab = s.find('\t', pos);
						if (tab == std::string::npos) { cols.push_back(s.substr(pos)); break; }
						cols.push_back(s.substr(pos, tab - pos)); pos = tab + 1;
						if (pos >= s.size()) break;
					}

					bool shouldInsert = true;
					std::string selStr;
					if (m_appCombo) {
						int sel = (int)SendMessageA(m_appCombo, CB_GETCURSEL, 0, 0);
						if (sel != CB_ERR) { char sb[256] = {}; SendMessageA(m_appCombo, CB_GETLBTEXT, sel, (LPARAM)sb); selStr = sb; }
					}
					if (!selStr.empty() && selStr != "All Applications") {
						std::string proccol = cols.size() > 8 ? cols[8] : std::string();
						while (!proccol.empty() && (proccol.back() == '\n' || proccol.back() == '\r'))proccol.pop_back();
						if (proccol != selStr) shouldInsert = false;
					}

					if (shouldInsert)
					{
						int itemIndex = (int)SendMessageA(m_packetList, LVM_GETITEMCOUNT, 0, 0);
						LVITEMA it{}; it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = itemIndex; it.lParam = (LPARAM)arr[i].idx;
						char idbuf[32]; snprintf(idbuf, sizeof(idbuf), "%d", arr[i].idx); it.pszText = idbuf;
						SendMessageA(m_packetList, LVM_INSERTITEMA, 0, (LPARAM)&it);
						for (int c = 0; c < (int)cols.size() && c < 9; ++c) {
							LVITEMA sub{}; sub.mask = LVIF_TEXT; sub.iItem = itemIndex; sub.iSubItem = c + 1;
							sub.pszText = const_cast<char*>(cols[c].c_str());
							SendMessageA(m_packetList, LVM_SETITEMA, 0, (LPARAM)&sub);
						}
					}

					if ((int)cols.size() > 8 && m_appCombo)
					{
						std::string proc = cols.size() > 8 ? cols[8] : std::string();
						while (!proc.empty() && (proc.back() == '\n' || proc.back() == '\r'))proc.pop_back();
						bool isReal = !proc.empty()
							&& proc.rfind("Error:", 0) != 0
							&& proc != "(Matilda)";
						if (isReal && SendMessageA(m_appCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)proc.c_str()) == CB_ERR) {
							SendMessageA(m_appCombo, CB_ADDSTRING, 0, (LPARAM)proc.c_str());
							if (m_logger) { std::ostringstream ss; ss << "Added application: " << proc << "\r\n"; m_logger->log(ss.str()); }
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
		PAINTSTRUCT ps; HDC hdc = BeginPaint(hWnd, &ps);
		RECT client; GetClientRect(hWnd, &client);

		const int topArea = 40, bottomControlsH = 100;
		int bottomTop = client.bottom - bottomControlsH;
		int rightX = m_splitPos + m_splitWidth;
		int rightW = client.right - rightX - 10;

				// Headbar (top area) and main background
				RECT headRect = { client.left, client.top, client.right, client.top + topArea };
				HBRUSH headBrush = CreateSolidBrush(m_theme.headbarBg); FillRect(hdc, &headRect, headBrush); DeleteObject(headBrush);

				RECT mainRect = { client.left, client.top + topArea, client.right, client.bottom };
				HBRUSH bgBrush = CreateSolidBrush(m_theme.bgWindow); FillRect(hdc, &mainRect, bgBrush); DeleteObject(bgBrush);

		// All splitters: thin coloured line centred in a narrow margin strip.
		// The margin is filled with splitterBg; a 1-px line in splitterLine
		// runs through the centre.  All three splitters share the same margin
		// colour so they "connect" visually at intersection points.
		auto drawVSplitter = [&](int x, int w, int y1, int y2) {
			RECT r = { x,y1,x + w,y2 };
			HBRUSH b = CreateSolidBrush(m_theme.splitterBg); FillRect(hdc, &r, b); DeleteObject(b);
			int cx = x + w / 2;
			HPEN pen = CreatePen(PS_SOLID, 1, m_theme.splitterLine); HPEN old = (HPEN)SelectObject(hdc, pen);
			MoveToEx(hdc, cx, y1, nullptr); LineTo(hdc, cx, y2);
			SelectObject(hdc, old); DeleteObject(pen);
			};
		auto drawHSplitter = [&](int y, int h, int x1, int x2) {
			RECT r = { x1,y,x2,y + h };
			HBRUSH b = CreateSolidBrush(m_theme.splitterBg); FillRect(hdc, &r, b); DeleteObject(b);
			int cy = y + h / 2;
			HPEN pen = CreatePen(PS_SOLID, 1, m_theme.splitterLine); HPEN old = (HPEN)SelectObject(hdc, pen);
			MoveToEx(hdc, x1, cy, nullptr); LineTo(hdc, x2, cy);
			SelectObject(hdc, old); DeleteObject(pen);
			};

		// Vertical splitter (console | packets) — full height between toolbar areas
		drawVSplitter(m_splitPos, m_splitWidth, topArea, bottomTop);

		// Horizontal splitter (list | detail) — right pane only
		drawHSplitter(m_hsplitPos, m_hsplitHeight, rightX, rightX + rightW);

		// Detail-area vertical splitter (hex | parsed panel)
		int detailTop = m_hsplitPos + m_hsplitHeight;
		int detailH = bottomTop - detailTop;
		if (detailH > 0 && m_detailSplitPos > 0) {
			int dsX = rightX + m_detailSplitPos;
			drawVSplitter(dsX, m_detailSplitWidth, detailTop, detailTop + detailH);
		}

		EndPaint(hWnd, &ps);
	}
	break;

	case WM_SIZE:
		RepositionControls(LOWORD(lParam), HIWORD(lParam));
		break;

	case WM_NOTIFY:
	{
		NMHDR* hdr = (NMHDR*)lParam;
		if (hdr && hdr->idFrom == 9)
		{
			if (hdr->code == LVN_ITEMCHANGED)
			{
				int sel = ListView_GetNextItem(m_packetList, -1, LVNI_SELECTED);
				if (sel >= 0)
				{
					wchar_t idbuf[64] = {}; ListView_GetItemText(m_packetList, sel, 0, idbuf, _countof(idbuf));
					int pktIdx = _wtoi(idbuf);
					std::vector<uint8_t> bytes;
					if (m_captureManager && m_captureManager->getCapturedPacketBytes((size_t)pktIdx, bytes))
					{
						// -------------------------------------------------------
						// Hex dump — three columns aligned: offset | hex | ascii
						// Each column is always the same width regardless of how
						// many bytes are on the last (short) row.
						//   offset : 8 hex digits + ": " = 10 chars
						//   hex    : 16 * "XX " = 48 chars (short rows padded with "   ")
						//   sep    : "  "        =  2 chars
						//   ascii  : 16 chars    (short rows padded with ' ')
						//   line end "\r\n"       =  2 chars
						// Total per row: 62 chars — MUST match HighlightHexRange
						// -------------------------------------------------------
						std::ostringstream oss;
						oss << std::hex << std::setfill('0');
						const size_t kBPL = 16;
						for (size_t off = 0; off < bytes.size(); off += kBPL)
						{
							// Offset column (10 chars: "XXXXXXXX: ")
							oss << std::setw(8) << off << ": ";
							// Hex column (always 48 chars = 16 * "XX ")
							for (size_t b = 0; b < kBPL; ++b) {
								if (off + b < bytes.size())
									oss << std::setw(2) << (int)bytes[off + b] << ' ';
								else
									oss << "   "; // 3 spaces to match "XX "
							}
							// Separator (2 chars)
							oss << "  ";
							// ASCII column (always 16 chars)
							for (size_t b = 0; b < kBPL; ++b) {
								if (off + b < bytes.size()) {
									uint8_t ch = bytes[off + b];
									oss << (char)((ch >= 32 && ch < 127) ? ch : '.');
								}
								else {
									oss << ' ';
								}
							}
							oss << "\r\n";
						}
						SetWindowTextA(m_packetDetail, oss.str().c_str());
						UpdateParsedPanel(bytes);

						// Populate preview fields from metadata
						std::vector<std::string> meta;
						if (m_captureManager->getCapturedMeta((size_t)pktIdx, meta))
						{
							std::string proto = meta.size() > 2 ? meta[2] : "TCP";
							std::string srcPort = meta.size() > 4 ? meta[4] : std::string();
							std::string dstIp = meta.size() > 5 ? meta[5] : std::string();
							std::string dstPort = meta.size() > 6 ? meta[6] : std::string();
							if (m_previewProtoCombo) SendMessageA(m_previewProtoCombo, CB_SETCURSEL, (proto == "UDP") ? 1 : 0, 0);
							if (m_previewSrcPort)  SetWindowTextA(m_previewSrcPort, srcPort.c_str());
							if (m_previewDstIp)    SetWindowTextA(m_previewDstIp, dstIp.c_str());
							if (m_previewDstPort)  SetWindowTextA(m_previewDstPort, dstPort.c_str());
						}

						// Extract transport payload as hex for the payload preview box
						std::string payloadHex;
						if (bytes.size() >= 14 + 20) {
							uint16_t ethType = (uint16_t)((bytes[12] << 8) | bytes[13]);
							if (ethType == 0x0800 && bytes.size() > 14 + 20) {
								size_t ipOff = 14; uint8_t ihl = (bytes[ipOff] & 0x0F) * 4;
								if (bytes.size() >= ipOff + ihl) {
									uint8_t protocol = bytes[ipOff + 9];
									size_t tpOff = ipOff + ihl; size_t thLen = 0;
									if (protocol == 6 && bytes.size() >= tpOff + 20) { uint8_t do2 = (bytes[tpOff + 12] >> 4) & 0xF; thLen = (size_t)do2 * 4; if (thLen < 20)thLen = 20; }
									else if (protocol == 17 && bytes.size() >= tpOff + 8) { thLen = 8; }
									size_t payOff = tpOff + thLen;
									if (bytes.size() > payOff) {
										std::ostringstream ph; ph << std::hex << std::setfill('0');
										for (size_t i = payOff; i < bytes.size(); ++i) ph << std::setw(2) << (int)bytes[i];
										payloadHex = ph.str();
									}
								}
							}
						}
						if (m_previewPayload) SetWindowTextA(m_previewPayload, payloadHex.c_str());
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
				NMLISTVIEW* nmlv = (NMLISTVIEW*)lParam;
				int col = nmlv ? nmlv->iSubItem : 0; if (col < 0)col = 0;
				if (col == m_sortCol) m_sortDesc = !m_sortDesc;
				else { m_sortCol = col; m_sortDesc = false; }
				LVSortParams* sp = new LVSortParams{ m_packetList,col,m_sortDesc };
				ListView_SortItems(m_packetList, ListViewCompare, (LPARAM)sp);
				delete sp;
			}
		}
	}
	break;

	case WM_LBUTTONDOWN:
	{
		int x = LOWORD(lParam), y = HIWORD(lParam);
		RECT rc; GetClientRect(hWnd, &rc);
		int rightX2 = m_splitPos + m_splitWidth, rightW2 = rc.right - rightX2 - 10;
		const int bottomControlsHeight = 100;
		int bottomTop = rc.bottom - bottomControlsHeight;
		int detailTop = m_hsplitPos + m_hsplitHeight;
		int detailH = bottomTop - detailTop;

		if (x >= m_splitPos && x <= m_splitPos + m_splitWidth)
		{
			m_vsplitDragging = true; SetCapture(hWnd);
		}
		else if (x >= rightX2 && x <= rightX2 + rightW2 && y >= m_hsplitPos && y <= m_hsplitPos + m_hsplitHeight)
		{
			m_hsplitDragging = true; SetCapture(hWnd);
		}
		else if (detailH > 0 && y >= detailTop && y < detailTop + detailH) {
			int dsx = rightX2 + m_detailSplitPos;
			if (x >= dsx && x <= dsx + m_detailSplitWidth)
			{
				m_detailSplitDragging = true; SetCapture(hWnd);
			}
		}
	}
	break;

	case WM_MOUSEMOVE:
	{
		int x = LOWORD(lParam), y = HIWORD(lParam);
		RECT rc; GetClientRect(hWnd, &rc);
		int rightX2 = m_splitPos + m_splitWidth, rightW2 = rc.right - rightX2 - 10;
		const int bottomControlsHeight = 100;
		int bottomTop = rc.bottom - bottomControlsHeight;
		int detailTop = m_hsplitPos + m_hsplitHeight;
		int detailH = bottomTop - detailTop;

		if (m_vsplitDragging) {
			int mn = 100, mx = rc.right - 300; if (mx < mn)mx = mn; if (x < mn)x = mn; if (x > mx)x = mx;
			m_splitPos = x; RepositionControls(rc.right, rc.bottom); InvalidateRect(hWnd, NULL, TRUE);
		}
		else if (m_hsplitDragging) {
			int mn = 40 + 80, mx = bottomTop - 80 - m_hsplitHeight; if (mn > mx)mx = mn; if (y < mn)y = mn; if (y > mx)y = mx;
			m_hsplitPos = y; RepositionControls(rc.right, rc.bottom); InvalidateRect(hWnd, NULL, TRUE);
		}
		else if (m_detailSplitDragging) {
			int relX = x - rightX2;
			int mn = 80, mx = rightW2 - 80 - m_detailSplitWidth; if (mx < mn)mx = mn; if (relX < mn)relX = mn; if (relX > mx)relX = mx;
			m_detailSplitPos = relX; RepositionControls(rc.right, rc.bottom); InvalidateRect(hWnd, NULL, TRUE);
		}
		else {
			bool onV = (x >= m_splitPos && x <= m_splitPos + m_splitWidth);
			bool onH = (x >= rightX2 && x <= rightX2 + rightW2 && y >= m_hsplitPos && y <= m_hsplitPos + m_hsplitHeight);
			int  dsx = rightX2 + m_detailSplitPos;
			bool onDS = (detailH > 0 && y >= detailTop && y < detailTop + detailH && x >= dsx && x <= dsx + m_detailSplitWidth);
			if (onV || onDS) SetCursor(LoadCursor(NULL, IDC_SIZEWE));
			else if (onH)  SetCursor(LoadCursor(NULL, IDC_SIZENS));
		}
	}
	break;

	case WM_LBUTTONUP:
		if (m_vsplitDragging || m_hsplitDragging || m_detailSplitDragging) {
			m_vsplitDragging = m_hsplitDragging = m_detailSplitDragging = false;
			ReleaseCapture();
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
	if (message == WM_CREATE) {
		CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
		pThis = (MainApp*)cs->lpCreateParams;
		SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
	}
	else pThis = (MainApp*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
	if (pThis) return pThis->HandleMessage(hWnd, message, wParam, lParam);
	return DefWindowProc(hWnd, message, wParam, lParam);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR lpCmdLine,
	_In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	MainApp app(hInstance);
	return app.Run(nCmdShow);
}