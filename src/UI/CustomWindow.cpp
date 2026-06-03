/*#include "CustomWindow.h"
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>

namespace UI {

struct FramelessData {
    int headbarH;
};

static LRESULT CALLBACK FramelessSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    FramelessData* fd = (FramelessData*)dwRefData;
    switch (msg)
    {
    case WM_NCCALCSIZE:
        // Remove standard non-client area so the whole window is client
        if (wParam)
        {
            // Let Windows know we've handled it
            return 0;
        }
        break;

    case WM_NCDESTROY:
    {
        // cleanup allocated frameless data
        if (fd) {
            RemoveWindowSubclass(hwnd, FramelessSubclassProc, uIdSubclass);
            delete fd;
        }
        break;
    }
        // Remove standard non-client area so the whole window is client
        if (wParam)
        {
            // Let Windows know we've handled it
            return 0;
        }
        break;

    case WM_NCHITTEST:
    {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        RECT wr; GetWindowRect(hwnd, &wr);
        int x = pt.x - wr.left;
        int y = pt.y - wr.top;

        const int border = 8; // resize border thickness
        const int cx = wr.right - wr.left;
        const int cy = wr.bottom - wr.top;

        // Corners
        bool left = x < border;
        bool right = x >= cx - border;
        bool top = y < border;
        bool bottom = y >= cy - border;

        if (left && top) return HTTOPLEFT;
        if (right && top) return HTTOPRIGHT;
        if (left && bottom) return HTBOTTOMLEFT;
        if (right && bottom) return HTBOTTOMRIGHT;

        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;

        // Headbar area -> act like caption for dragging, but leave left/settings and right window-button areas as client
        if (fd && y >= 0 && y < fd->headbarH)
        {
            int leftInteractive = 200; // pixels reserved for left interactive items (Settings)
            int rightButtonsWidth = 132; // 3 * 40 + gaps
            if (x >= leftInteractive && x < cx - rightButtonsWidth)
                return HTCAPTION;
            else
                return HTCLIENT;
        }

        return HTCLIENT;
    }
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

bool EnableFrameless(HWND hwnd, int headbarHeight)
{
    if (!IsWindow(hwnd)) return false;
    // Ensure window has sizable border so resizing still works; keep WS_THICKFRAME
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    style |= WS_THICKFRAME; // ensure resizing
    style &= ~WS_CAPTION; // remove caption
    SetWindowLongPtr(hwnd, GWL_STYLE, style);

    FramelessData* fd = new FramelessData(); fd->headbarH = headbarHeight;
    // Use SetWindowSubclass to avoid replacing app's main wndproc
    BOOL ok = SetWindowSubclass(hwnd, FramelessSubclassProc, 0xC0FFEE, (DWORD_PTR)fd);
    return ok == TRUE;
}

} // namespace UI
*/