#include "ThemeLight.h"

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