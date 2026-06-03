#include "UIElement.h"
#include <string>

namespace UI {

HFONT s_uiFont = nullptr;
HFONT s_monoFont = nullptr;

void UpdateGlobalFonts(const Theme& theme)
{
    (void)theme; // theme may influence font choices in future
    if (s_uiFont) { DeleteObject(s_uiFont); s_uiFont = nullptr; }
    if (s_monoFont) { DeleteObject(s_monoFont); s_monoFont = nullptr; }

    // Default sizes chosen to match previous behavior (-13 logical height)
    s_uiFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    s_monoFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_MODERN, "Segoe UI Mono");
}

} // namespace UI
