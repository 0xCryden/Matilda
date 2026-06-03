#pragma once

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
