#include "UITitlebar.h"
#include "UIWindow.h"
#include <windowsx.h>
#include "../../Utils/Constants.h"
#include <string>

UITitlebar::UITitlebar(int x, int y, int w, int h, int id, UIWindow* window)
    : UIElement(x, y, w, h, id), m_window(window)
{
}

void UITitlebar::Draw(HDC hdc, UITheme* theme)
{
    UIRect r{ m_x, m_y, m_w, m_h };

    theme->DrawTitlebar(
        hdc,
        r,
        m_window,
        (int)m_state
    );
}

void UITitlebar::OnMouseDown(int x, int y, UIEventQueue& events)
{
    m_dragging = true;
    m_window->SetCapture(this);

    POINT p;
    GetCursorPos(&p);

    RECT rc;
    GetWindowRect(m_window->GetHWND(), &rc);

    m_dragOffsetX = p.x - rc.left;
    m_dragOffsetY = p.y - rc.top;
}

void UITitlebar::OnMouseUp(int x, int y, UIEventQueue& events)
{
    m_dragging = false;
    m_window->ReleaseCapture();
}

void UITitlebar::OnMouseMove(int x, int y)
{
    if (!m_dragging)
        return;

    POINT p;
    GetCursorPos(&p);

    SetWindowPos(
        m_window->GetHWND(),
        nullptr,
        p.x - m_dragOffsetX,
        p.y - m_dragOffsetY,
        0, 0,
        SWP_NOZORDER | SWP_NOSIZE
    );
}