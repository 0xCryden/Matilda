#pragma once
#include "UIElement.h"
#include <string>

class UIButton : public UIElement
{
public:
    UIButton(int x, int y, int w, int h, int id, const wchar_t* text);

    void Draw(HDC hdc, UITheme* theme) override;

    void OnMouseDown(int mx, int my, UIEventQueue& events) override;

private:
    std::wstring m_text;
};

/*#pragma once

#include "UIElement.h"
#include <string>

namespace UI {

class UIButton : public UIElement {
public:
    UIButton();
    virtual ~UIButton();

    HWND Create(HWND parent, int id, RECT rc) override;
    void Destroy() override;
    void SetText(const std::string& txt);

    // Owner-draw entry point wired from parent WM_DRAWITEM
    static void DrawItem(LPDRAWITEMSTRUCT dis);
};

} // namespace UI
*/