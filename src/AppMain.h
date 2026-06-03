#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <unordered_set>
#include "Themes.h"
#include "UI\UIButton.h"

class Logger;
class CaptureManager;

// A single parsed protocol field: name, byte range in the raw frame, human-readable value
struct ParsedField {
    std::string name;       // e.g. "Src IP", "TCP Seq"
    std::string layerTag;   // e.g. "ETH", "IP", "TCP", "UDP"
    size_t      byteOffset; // offset from start of raw frame
    size_t      byteLen;    // number of bytes this field occupies
    std::string value;      // human-readable formatted value
};

class MainApp {
public:
    MainApp(HINSTANCE hInstance);
    int Run(int nCmdShow);
    const Theme& GetTheme() const { return m_theme; }

private:
    HINSTANCE hInst;
    wchar_t szTitle[100];
    wchar_t szWindowClass[100];
    Theme m_theme;

    HWND m_outputBox;
    HWND m_mainWindow;
    HWND m_deviceCombo;
    HWND m_appCombo;
    HWND m_packetList;
    HWND m_packetDetail;    // hex dump EDIT (left half of detail area)

    // Right half of detail area: owner-drawn parsed-fields panel
    HWND m_parsedPanel;
    HWND m_parsedTooltip;

    // Preview / send row controls (bottom toolbar)
    HWND m_previewProtoCombo;
    HWND m_previewSrcPort;
    HWND m_previewDstIp;
    HWND m_previewDstPort;
    HWND m_previewPayload;

    // Themed owner-drawn buttons (wrappers)
    std::unique_ptr<UI::UIButton> m_btnStartObj;
    std::unique_ptr<UI::UIButton> m_btnReplayObj;
    std::unique_ptr<UI::UIButton> m_btnSendObj;
    std::unique_ptr<UI::UIButton> m_btnFilterObj;

    // Custom scrollbars for parsed panel and packet detail
    std::unique_ptr<UI::UIScrollbar> m_parsedScrollbarObj;
    std::unique_ptr<UI::UIScrollbar> m_packetDetailScrollbarObj;

    // Settings menu stored for headbar popup
    HMENU m_settingsMenu;
    int m_headbarHeight;
    // m_previewHexCheckbox removed � payload field interprets hex directly

    // Vertical splitter (left log pane | right packet pane)
    int  m_splitPos;
    int  m_splitWidth;
    bool m_vsplitDragging;

    // Horizontal splitter within right pane (list | detail)
    int  m_hsplitPos;
    int  m_hsplitHeight;
    bool m_hsplitDragging;

    // Vertical splitter inside detail area (hex view | parsed panel)
    int  m_detailSplitPos;
    int  m_detailSplitWidth;
    bool m_detailSplitDragging;

    // Sorting state for packet list
    int  m_sortCol;
    bool m_sortDesc;

    // Parsed fields for currently selected packet
    std::vector<ParsedField>  m_parsedFields;
    std::vector<uint8_t>      m_currentBytes;
    int                       m_hoveredField;
    std::unordered_set<std::string> m_collapsedLayers;

    static const int PARSED_ROW_H = 18;

    std::unique_ptr<Logger>         m_logger;
    std::unique_ptr<CaptureManager> m_captureManager;
    bool m_capturing;

    // --- helpers ---
    void SetupListViewColumns();
    void AppendText(const std::string& text);
    void PopulateDeviceList();
    void PopulateProcessCombo(HWND combo);
    void OnStartCapture();
    void OnStopCapture();
    void RepositionControls(int clientW, int clientH);

    // Apply current m_theme to all child controls and repaint
    void ApplyTheme();

    // Packet parsing
    static std::vector<ParsedField> ParsePacketFields(const std::vector<uint8_t>& bytes);

    // Parsed panel helpers
    void UpdateParsedPanel(const std::vector<uint8_t>& bytes);
    void PaintParsedPanel(HDC hdc, const RECT& rc);
    void HighlightHexRange(size_t byteOffset, size_t byteLen);

    // Custom window procs
    LRESULT HandleMessage(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT HandleParsedPanelMessage(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

    static LRESULT CALLBACK StaticWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK StaticParsedPanelProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
};