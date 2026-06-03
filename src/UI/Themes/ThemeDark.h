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
};