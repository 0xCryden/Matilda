#include "UIWindow.h"

UIWindow::UIWindow(HWND hwnd)
    : UIElement(0, 0, 0, 0, -1), m_hwnd(hwnd)
{
}

void UIWindow::SetSize(int w, int h)
{
    m_w = w;
    m_h = h;
}

void UIWindow::Draw(HDC hdc, UITheme* theme)
{
    for (auto* c : m_children)
        c->Draw(hdc, theme);
}

void UIWindow::OnMouseDown(int mx, int my, UIEventQueue& events)
{
    for (auto* c : m_children)
    {
        if (c->HitTest(mx, my))
        {
            c->OnMouseDown(mx, my, events);
            return;
        }
    }
}

void UIWindow::OnMouseUp(int mx, int my, UIEventQueue& events)
{
    if (m_capturedElement)
    {
        m_capturedElement->OnMouseUp(mx, my, events);
        return;
    }

    for (auto* c : m_children)
    {
        if (c->HitTest(mx, my))
        {
            c->OnMouseUp(mx, my, events);
            return;
        }
    }
}

void UIWindow::OnMouseMove(int mx, int my)
{
    if (m_capturedElement)
    {
        m_capturedElement->OnMouseMove(mx, my);
        return;
    }

    UIElement* newHovered = nullptr;

    for (auto* c : m_children)
    {
        if (c->HitTest(mx, my))
        {
            newHovered = c;
            break;
        }
    }

    if (newHovered != m_hoveredElement)
    {
        if (m_hoveredElement)
            m_hoveredElement->SetState(UIElementState::Normal);

        if (newHovered)
            newHovered->SetState(UIElementState::Hovered);

        m_hoveredElement = newHovered;

        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
}

void UIWindow::SetCapture(UIElement* element)
{
    m_capturedElement = element;
    ::SetCapture(m_hwnd);
}

void UIWindow::ReleaseCapture()
{
    m_capturedElement = nullptr;
    ::ReleaseCapture();
}

HWND UIWindow::GetHWND() const
{
    return m_hwnd;
}
/*#include "UIWindow.h"
#include "../AppMain.h"
#include <string>

namespace UI {

    UIWindow::UIWindow() { m_hwnd = nullptr; m_id = 0; }
    UIWindow::~UIWindow() { Destroy(); }

    HWND UIWindow::Create(HWND parent, int id, RECT rc)
    {
        m_id = id;
        // Button styles: owner-draw push button
        DWORD style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW;
        m_hwnd = CreateWindowA("BUTTON", "", style,
            rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
            parent, (HMENU)(INT_PTR)id, GetModuleHandle(nullptr), nullptr);
        return m_hwnd;
    }

    void UIWindow::Destroy()
    {
        if (m_hwnd) { DestroyWindow(m_hwnd); m_hwnd = nullptr; }
    }

    void UIWindow::SetText(const std::string& txt)
    {
        if (m_hwnd) SetWindowTextA(m_hwnd, txt.c_str());
    }

    void UIWindow::DrawItem(LPDRAWITEMSTRUCT dis)
    {
        if (!dis) return;
        HWND hBtn = dis->hwndItem;
        HWND parent = GetParent(hBtn);
        // Try to obtain theme from parent MainApp instance
        MainApp* app = nullptr;
        if (parent) app = (MainApp*)GetWindowLongPtr(parent, GWLP_USERDATA);

        Theme th = app ? app->GetTheme() : Themes::White();

        HDC hdc = dis->hDC;
        RECT rc = dis->rcItem;

        // Fill background
        HBRUSH b = CreateSolidBrush(th.bgButton);
        FillRect(hdc, &rc, b);
        DeleteObject(b);

        // Draw border
        HPEN pen = CreatePen(PS_SOLID, 1, th.btnBorder);
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);

        // Draw text centered
        char buf[256] = {};
        GetWindowTextA(hBtn, buf, sizeof(buf));

        HFONT oldF = nullptr;
        if (s_uiFont) oldF = (HFONT)SelectObject(hdc, s_uiFont);

        SetTextColor(hdc, th.textColor);
        SetBkMode(hdc, TRANSPARENT);

        DrawTextA(hdc, buf, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        if (oldF) SelectObject(hdc, oldF);

        // Focus rectangle
        if (dis->itemState & ODS_FOCUS)
        {
            RECT frc = rc; InflateRect(&frc, -4, -4);
            DrawFocusRect(hdc, &frc);
        }
    }

} // namespace UI
*/