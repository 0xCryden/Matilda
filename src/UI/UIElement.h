#pragma once

#include <windows.h>
#include "../Themes.h"

namespace UI {

extern HFONT s_uiFont;
extern HFONT s_monoFont;

// Create or update global fonts used by the UI layer
void UpdateGlobalFonts(const Theme& theme);

class UIElement {
public:
    UIElement() : m_hwnd(nullptr), m_id(0) {}
    virtual ~UIElement() {}

    // Create control as child of parent. rect is in parent client coords.
    virtual HWND Create(HWND parent, int id, RECT rc) = 0;
    virtual void Destroy() { if (m_hwnd) { DestroyWindow(m_hwnd); m_hwnd = nullptr; } }
    virtual void ApplyTheme(const Theme& theme) { (void)theme; }

    HWND GetHwnd() const { return m_hwnd; }
protected:
    HWND m_hwnd;
    int  m_id;
};

} // namespace UI
