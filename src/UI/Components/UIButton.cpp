#include "UIButton.h"
#include "../UITheme.h"
#include "../UIEventQueue.h"

UIButton::UIButton(int x, int y, int w, int h, int id, const wchar_t* text)
    : UIElement(x, y, w, h, id), m_text(text)
{
}

void UIButton::Draw(HDC hdc, UITheme* theme)
{
    UIRect r{ m_x, m_y, m_w, m_h };

    theme->DrawButton(
        hdc,
        r,
        m_text.c_str(),
        (int)m_state
    );
}

void UIButton::OnMouseDown(int mx, int my, UIEventQueue& events)
{
    events.Push({ UICommand::ButtonClicked, m_id });
}

/*#include "UIButton.h"
#include "../AppMain.h"
#include <string>

namespace UI {

UIButton::UIButton() { m_hwnd = nullptr; m_id = 0; }
UIButton::~UIButton() { Destroy(); }

HWND UIButton::Create(HWND parent, int id, RECT rc)
{
    m_id = id;
    // Button styles: owner-draw push button
    DWORD style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW;
    m_hwnd = CreateWindowA("BUTTON", "", style,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
        parent, (HMENU)(INT_PTR)id, GetModuleHandle(nullptr), nullptr);
    return m_hwnd;
}

void UIButton::Destroy()
{
    if (m_hwnd) { DestroyWindow(m_hwnd); m_hwnd = nullptr; }
}

void UIButton::SetText(const std::string& txt)
{
    if (m_hwnd) SetWindowTextA(m_hwnd, txt.c_str());
}

void UIButton::DrawItem(LPDRAWITEMSTRUCT dis)
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