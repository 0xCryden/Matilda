#pragma once
#include <string_view>

namespace Constants
{
    inline constexpr const wchar_t* AppName = L"Matilda";
    inline constexpr const wchar_t* MainWindowClass = L"MyAppWindow";
    inline constexpr int DefaultWindowWidth = 1280;
    inline constexpr int DefaultWindowHeight = 720;

    inline constexpr int WindowBorderThickness = 8;
    inline constexpr int TitlebarHeight = 40;

    // colors (example)
    inline constexpr unsigned int ColorBackground = 0x2B2B2B;
    inline constexpr unsigned int ColorButtonNormal = 0x3C3C3C;
    inline constexpr unsigned int ColorButtonHover = 0x505050;
}