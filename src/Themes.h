#pragma once

#include <windows.h>

struct Theme
{
    COLORREF bgWindow;//backgroundColor;
    COLORREF textColor;
    COLORREF splitterBg;//panelColor;
    COLORREF splitterLine;//accentColor;
};

class Themes
{
public:
    static Theme White()
    {
        return Theme{
            RGB(255, 255, 255), // background
            RGB(0, 0, 0),       // text
            RGB(240, 240, 240), // panels
            RGB(0, 120, 215)    // accent
        };
    }

    static Theme Dark()
    {
        return Theme{
            RGB(30, 30, 30),
            RGB(220, 220, 220),
            RGB(45, 45, 48),
            RGB(0, 120, 215)
        };
    }
};