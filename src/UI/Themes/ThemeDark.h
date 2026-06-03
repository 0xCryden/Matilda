#pragma once
#include "../UITheme.h"

class ThemeDark : public UITheme
{
public:
    void DrawButton(
        HDC hdc,
        const UIRect& rect,
        const wchar_t* text,
        int state
    ) override;

    void DrawTitlebar(
        HDC hdc,
        const UIRect& rect,
        UIWindow* window,
        int state
    ) override;
};