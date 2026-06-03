#pragma once
#include "../UITheme.h"

class ThemeLight : public UITheme
{
public:
    void DrawButton(
        HDC hdc,
        const UIRect& rect,
        const wchar_t* text,
        int state
    ) override;
};