#include "ThemeLight.h"
#include "../../Utils/Constants.h"

void ThemeLight::DrawButton(
    HDC hdc,
    const UIRect& rect,
    const wchar_t* text,
    int state)
{
    COLORREF bg =
        (state == 1) ? RGB(200, 200, 200) :
        (state == 2) ? RGB(160, 160, 160) :
        RGB(220, 220, 220);

    RECT r{ rect.x, rect.y, rect.x + rect.w, rect.y + rect.h };

    HBRUSH brush = CreateSolidBrush(bg);
    FillRect(hdc, &r, brush);
    DeleteObject(brush);

    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, rect.x + 6, rect.y + 6, text, lstrlenW(text));
}

void ThemeLight::DrawTitlebar(
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