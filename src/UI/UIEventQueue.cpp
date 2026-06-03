#include "UIEventQueue.h"

void UIEventQueue::Push(const UIEvent& event)
{
    m_queue.push(event);
}

bool UIEventQueue::Pop(UIEvent& event)
{
    if (m_queue.empty())
        return false;

    event = m_queue.front();
    m_queue.pop();
    return true;
}