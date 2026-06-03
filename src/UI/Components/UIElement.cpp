#include "UIElement.h"
#include "../UIEventQueue.h"

UIElement::UIElement(int x, int y, int w, int h, int id)
    : m_x(x), m_y(y), m_w(w), m_h(h), m_id(id)
{
}

UIElement::~UIElement()
{
    for (auto* c : m_children)
        delete c;
}

bool UIElement::HitTest(int mx, int my) const
{
    return mx >= m_x && mx <= m_x + m_w &&
        my >= m_y && my <= m_y + m_h;
}

void UIElement::AddChild(UIElement* child)
{
    m_children.push_back(child);
}

int UIElement::GetId() const
{
    return m_id;
}

void UIElement::OnMouseDown(int mx, int my, UIEventQueue& events)
{
    for (auto* child : m_children)
    {
        if (child->HitTest(mx, my))
        {
            child->OnMouseDown(mx, my, events);
            return;
        }
    }
}

void UIElement::OnMouseMove(int mx, int my)
{
    /*bool inside = HitTest(mx, my);

    m_state = inside
        ? UIElementState::Hovered
        : UIElementState::Normal;*/

    for (auto* child : m_children)
        child->OnMouseMove(mx, my);
}

void UIElement::SetState(UIElementState state)
{
    m_state = state;
}

/*#include "UIElement.h"
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
*/