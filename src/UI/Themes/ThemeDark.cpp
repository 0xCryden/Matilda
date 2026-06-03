#include "ThemeDark.h"
#include "../Components/UIElement.h"
#include "../../Utils/Constants.h"

void ThemeDark::DrawButton(
    HDC hdc,
    const UIRect& rect,
    const wchar_t* text,
    int state)
{
    COLORREF bg;

    switch ((UIElementState)state)
    {
    case UIElementState::Hovered:
        bg = RGB(180, 180, 180);
        break;

    case UIElementState::Pressed:
        bg = RGB(140, 140, 140);
        break;

    default:
        bg = RGB(220, 220, 220);
        break;
    }

    RECT r{ rect.x, rect.y, rect.x + rect.w, rect.y + rect.h };

    HBRUSH brush = CreateSolidBrush(bg);
    FillRect(hdc, &r, brush);
    DeleteObject(brush);

    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, rect.x + 6, rect.y + 6, text, lstrlenW(text));
}

void ThemeDark::DrawTitlebar(
    HDC hdc,
    const UIRect& rect,
    UIWindow* window,
    int state)
{
    RECT r{ rect.x, rect.y, rect.x + rect.w, rect.y + rect.h };
    COLORREF bg = RGB(180, 180, 180);
    COLORREF textColor = RGB(30, 30, 30);

    // background
    HBRUSH brush = CreateSolidBrush(bg);
    FillRect(hdc, &r, brush);
    DeleteObject(brush);

    // title text
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, textColor);

    //std::wstring title = Constants::AppName; // later: from App / Constants

    RECT textRc = r;
    textRc.left += 10;

    DrawTextW(hdc, Constants::AppName, -1, &textRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}