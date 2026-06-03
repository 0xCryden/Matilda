#pragma once
#include "UIElement.h"
#include "../ThemeManager.h"

class UIWindow : public UIElement
{
public:
    UIWindow(HWND hwnd);

    void SetSize(int w, int h);

    void Draw(HDC hdc, UITheme* theme) override;

    void OnMouseDown(int mx, int my, UIEventQueue& events) override;
    void OnMouseUp(int mx, int my, UIEventQueue& events) override;
    void OnMouseMove(int mx, int my) override;

    void SetCapture(UIElement* element);
    void ReleaseCapture();

    HWND GetHWND() const;

private:
    HWND m_hwnd;

    UIElement* m_capturedElement = nullptr;
    UIElement* m_hoveredElement = nullptr;
};

/*#pragma once

#include "UIElement.h"
#include <string>

namespace UI {

    class UIWindow : public UIElement {
    public:
        UIWindow();
        virtual ~UIWindow();

        HWND Create(HWND parent, int id, RECT rc) override;
        void Destroy() override;
        void SetText(const std::string& txt);

        // Owner-draw entry point wired from parent WM_DRAWITEM
        static void DrawItem(LPDRAWITEMSTRUCT dis);
    };

} // namespace UI
*/