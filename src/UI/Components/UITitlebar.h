#pragma once
#include "UIElement.h"

class UIWindow;

class UITitlebar : public UIElement
{
public:
    UITitlebar(int x, int y, int w, int h, int id, UIWindow* window);

    void Draw(HDC hdc, UITheme* theme) override;

    void OnMouseDown(int x, int y, UIEventQueue& events) override;
    void OnMouseUp(int mx, int my, UIEventQueue& events) override;
    void OnMouseMove(int x, int y) override;

private:
    UIWindow* m_window;

    bool m_dragging = false;
    int m_dragOffsetX = 0;
    int m_dragOffsetY = 0;
};
