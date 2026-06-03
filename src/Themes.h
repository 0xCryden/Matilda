#pragma once

#include <windows.h>

struct Theme
{
    COLORREF bgWindow;        // main window background
    COLORREF textColor;       // general text
    COLORREF splitterBg;      // splitter background / panel area
    COLORREF splitterLine;    // splitter line / accent

    // Additional themeable elements
    COLORREF bgButton;        // button background
    COLORREF btnBorder;       // button border / accent
    COLORREF dropdownBg;      // dropdown list background
    COLORREF dropdownBtn;     // dropdown arrow/button background
    COLORREF scrollbarBg;     // background behind scrollbars
    COLORREF tableBg;         // table / listview background
    COLORREF headbarBg;       // top headbar (toolbar/menu area)
};

class Themes
{
public:
    static Theme White()
    {
        return Theme{
            RGB(255, 255, 255), // bgWindow
            RGB(0, 0, 0),       // textColor
            RGB(240, 240, 240), // splitterBg
            RGB(0, 120, 215),   // splitterLine

            RGB(245, 245, 245), // bgButton
            RGB(200, 200, 200), // btnBorder
            RGB(255, 255, 255), // dropdownBg
            RGB(240, 240, 240), // dropdownBtn
            RGB(250, 250, 250), // scrollbarBg
            RGB(255, 255, 255), // tableBg
            RGB(245, 245, 245)  // headbarBg
        };
    }

    static Theme Dark()
    {
        return Theme{
            RGB(30, 30, 30),    // bgWindow
            RGB(220, 220, 220), // textColor
            RGB(45, 45, 48),    // splitterBg
            RGB(0, 120, 215),   // splitterLine

            RGB(60, 60, 64),    // bgButton
            RGB(80, 80, 90),    // btnBorder
            RGB(50, 50, 54),    // dropdownBg
            RGB(60, 60, 64),    // dropdownBtn
            RGB(40, 40, 44),    // scrollbarBg
            RGB(45, 45, 48),    // tableBg
            RGB(45, 45, 48)     // headbarBg
        };
    }
};