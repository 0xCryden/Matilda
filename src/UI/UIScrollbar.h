#pragma once

#include "UIElement.h"

namespace UI {

class UIScrollbar : public UIElement {
public:
    UIScrollbar();
    virtual ~UIScrollbar();

    HWND Create(HWND parent, int id, RECT rc) override;
    void Destroy() override;

    void SetRange(int min, int max, int page);
    void SetPosition(int pos);
    int GetPosition() const;

    // Target window that receives WM_VSCROLL notifications
    void SetTarget(HWND target) { m_target = target; }

private:
    int m_min, m_max, m_page, m_pos;
    bool m_dragging;
    int m_dragOffset; // y offset inside thumb when dragging
    HWND m_target;

    static LRESULT CALLBACK ScrollProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void OnPaint();
    void OnLButtonDown(int y);
    void OnMouseMove(int y);
    void OnLButtonUp();
};

} // namespace UI
