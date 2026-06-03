/*#include "UIScrollbar.h"
#include "../AppMain.h"
#include <windowsx.h>

namespace UI {

static const char* kScrollClass = "MatildaUIScrollbar";

UIScrollbar::UIScrollbar()
    : m_min(0), m_max(0), m_page(1), m_pos(0), m_dragging(false), m_dragOffset(0), m_target(nullptr)
{
}

UIScrollbar::~UIScrollbar() { Destroy(); }

HWND UIScrollbar::Create(HWND parent, int id, RECT rc)
{
    m_id = id;
    // Register class if needed
    WNDCLASSEXA wc{}; wc.cbSize = sizeof(wc);
    if (!GetClassInfoExA(GetModuleHandle(nullptr), kScrollClass, &wc)) {
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = ScrollProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = kScrollClass;
        RegisterClassExA(&wc);
    }

    m_hwnd = CreateWindowExA(0, kScrollClass, "",
        WS_CHILD | WS_VISIBLE,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
        parent, (HMENU)(INT_PTR)id, GetModuleHandle(nullptr), this);
    return m_hwnd;
}

void UIScrollbar::Destroy()
{
    if (m_hwnd) { DestroyWindow(m_hwnd); m_hwnd = nullptr; }
}

void UIScrollbar::SetRange(int min, int max, int page)
{
    m_min = min; m_max = max; m_page = page;
    if (m_pos < m_min) m_pos = m_min;
    if (m_pos > m_max) m_pos = m_max;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, TRUE);
}

void UIScrollbar::SetPosition(int pos)
{
    if (pos < m_min) pos = m_min;
    if (pos > m_max) pos = m_max;
    m_pos = pos;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, TRUE);
}

int UIScrollbar::GetPosition() const { return m_pos; }

LRESULT CALLBACK UIScrollbar::ScrollProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    UIScrollbar* self = (UIScrollbar*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    if (msg == WM_CREATE)
    {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        self = (UIScrollbar*)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)self);
    }
    if (!self) return DefWindowProc(hwnd, msg, wParam, lParam);

    switch (msg)
    {
    case WM_PAINT: self->OnPaint(); return 0;
    case WM_LBUTTONDOWN: SetCapture(hwnd); self->m_dragging = true; self->OnLButtonDown(GET_Y_LPARAM(lParam)); return 0;
    case WM_MOUSEMOVE: if (self->m_dragging) { self->OnMouseMove(GET_Y_LPARAM(lParam)); } return 0;
    case WM_LBUTTONUP: if (self->m_dragging) { self->m_dragging = false; ReleaseCapture(); self->OnLButtonUp(); } return 0;
    case WM_SIZE: InvalidateRect(hwnd, nullptr, TRUE); return 0;
    default: break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void UIScrollbar::OnPaint()
{
    PAINTSTRUCT ps; HDC hdc = BeginPaint(m_hwnd, &ps);
    RECT rc; GetClientRect(m_hwnd, &rc);
    HWND parent = GetParent(m_hwnd);
    MainApp* app = parent ? (MainApp*)GetWindowLongPtr(parent, GWLP_USERDATA) : nullptr;
    Theme th = app ? app->GetTheme() : Themes::White();

    HBRUSH b = CreateSolidBrush(th.scrollbarBg);
    FillRect(hdc, &rc, b);
    DeleteObject(b);

    // Thumb computation
    int clientH = rc.bottom - rc.top;
    int range = max(1, m_max - m_min + 1);
    // Thumb height proportional to page size
    int thumbH = max(18, (int)((double)m_page / (double)range * clientH));
    int trackH = clientH - thumbH;
    int posRatio = range > 1 ? (m_pos - m_min) * 1000 / (range - 1) : 0;
    int thumbY = rc.top + (int)((posRatio / 1000.0) * (double)trackH);

    RECT tr = { rc.left + 2, thumbY + 2, rc.right - 2, thumbY + thumbH - 2 };
    HBRUSH tb = CreateSolidBrush(th.btnBorder);
    FillRect(hdc, &tr, tb);
    DeleteObject(tb);

    EndPaint(m_hwnd, &ps);
}

void UIScrollbar::OnLButtonDown(int y)
{
    RECT rc; GetClientRect(m_hwnd, &rc);
    int clientH = rc.bottom - rc.top;
    int range = max(1, m_max - m_min + 1);
    int thumbH = max(18, (int)((double)m_page / (double)range * clientH));
    int trackH = clientH - thumbH;
    int posRatio = range > 1 ? (m_pos - m_min) * 1000 / (range - 1) : 0;
    int thumbY = (int)((posRatio / 1000.0) * (double)trackH);

    if (y >= thumbY && y <= thumbY + thumbH)
    {
        m_dragOffset = y - thumbY;
    }
    else
    {
        // Clicked on track; move by page
        if (y < thumbY) SetPosition(m_pos - m_page);
        else SetPosition(m_pos + m_page);
        // Notify target
        if (m_target) SendMessage(m_target, WM_VSCROLL, MAKEWPARAM(SB_PAGEUP, 0), (LPARAM)m_hwnd);
    }
}

void UIScrollbar::OnMouseMove(int y)
{
    RECT rc; GetClientRect(m_hwnd, &rc);
    int clientH = rc.bottom - rc.top;
    int range = max(1, m_max - m_min + 1);
    int thumbH = max(18, (int)((double)m_page / (double)range * clientH));
    int trackH = clientH - thumbH;
    int newThumbY = y - m_dragOffset;
    if (newThumbY < 0) newThumbY = 0;
    if (newThumbY > trackH) newThumbY = trackH;

    int newPos = m_min + (int)((double)newThumbY / (double)trackH * (double)(range - 1));
    if (newPos != m_pos) {
        m_pos = newPos;
        InvalidateRect(m_hwnd, nullptr, TRUE);
        if (m_target) SendMessage(m_target, WM_VSCROLL, MAKEWPARAM(SB_THUMBTRACK, m_pos), (LPARAM)m_hwnd);
    }
}

void UIScrollbar::OnLButtonUp()
{
    if (m_target) SendMessage(m_target, WM_VSCROLL, MAKEWPARAM(SB_THUMBPOSITION, m_pos), (LPARAM)m_hwnd);
}

} // namespace UI
*/