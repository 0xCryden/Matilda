#pragma once
#include <windows.h>
#include <vector>

class UITheme;
class UIEventQueue;
class UIWindow;

enum class UIElementState
{
    Normal,
    Hovered,
    Pressed,
    Disabled
};

class UIElement
{
public:
    UIElement(int x, int y, int w, int h, int id);
    virtual ~UIElement();

    virtual void Draw(HDC hdc, UITheme* theme) = 0;

    virtual void OnMouseDown(int mx, int my, UIEventQueue& events);
    virtual void OnMouseUp(int mx, int my, UIEventQueue& events);
    virtual void OnMouseMove(int mx, int my);

    bool HitTest(int mx, int my) const;

    void AddChild(UIElement* child);

    int GetId() const;

    void SetState(UIElementState state);
    UIElementState GetState() const { return m_state; }

    HWND GetHWND() const;

protected:
    UIWindow* m_window = nullptr;

    int m_x;
    int m_y;
    int m_w;
    int m_h;
    int m_id;

    UIElementState m_state = UIElementState::Normal;

    std::vector<UIElement*> m_children;
};

/*#pragma once

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
*/