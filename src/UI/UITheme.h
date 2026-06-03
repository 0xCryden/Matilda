#pragma once
#include <windows.h>

struct UIRect
{
    int x, y, w, h;
};

class UITheme
{
public:
    virtual ~UITheme() {}

    virtual void DrawButton(
        HDC hdc,
        const UIRect& rect,
        const wchar_t* text,
        int state
    ) = 0;
};