/*#include "UIComboDecorator.h"
#include "../AppMain.h"
#include <commctrl.h>
#include <windowsx.h>

namespace UI {

LRESULT CALLBACK UIComboDecorator::ComboSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        // Let default paint first
        LRESULT r = DefSubclassProc(hWnd, msg, wParam, lParam);
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc; GetClientRect(hWnd, &rc);
        HWND parent = GetParent(hWnd);
        MainApp* app = parent ? (MainApp*)GetWindowLongPtr(parent, GWLP_USERDATA) : nullptr;
        Theme th = app ? app->GetTheme() : Themes::White();

        // Determine dropdown button area (rightmost 20-24px)
        int btnW = GetSystemMetrics(SM_CXVSCROLL);
        RECT btnRect = { rc.right - btnW, rc.top, rc.right, rc.bottom };
        HBRUSH b = CreateSolidBrush(th.dropdownBtn);
        FillRect(hdc, &btnRect, b);
        DeleteObject(b);

        // Draw down arrow centered
        int cx = (btnRect.left + btnRect.right) / 2;
        int cy = (btnRect.top + btnRect.bottom) / 2;
        POINT pts[3] = { {cx - 6, cy - 2}, {cx + 6, cy - 2}, {cx, cy + 4} };
        HBRUSH br = CreateSolidBrush(th.textColor);
        HPEN pen = CreatePen(PS_SOLID, 1, th.textColor);
        HBRUSH oldB = (HBRUSH)SelectObject(hdc, br);
        HPEN oldP = (HPEN)SelectObject(hdc, pen);
        Polygon(hdc, pts, 3);
        SelectObject(hdc, oldP); SelectObject(hdc, oldB);
        DeleteObject(br); DeleteObject(pen);

        EndPaint(hWnd, &ps);
        return r;
    }
    default:
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

bool UIComboDecorator::Install(HWND combo)
{
    if (!IsWindow(combo)) return false;
    BOOL ok = SetWindowSubclass(combo, ComboSubclassProc, 0xC0DE, 0);
    return ok == TRUE;
}

} // namespace UI
*/