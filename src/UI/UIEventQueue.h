#pragma once
#include "UIEvent.h"
#include <queue>

class UIEventQueue
{
public:
    void Push(const UIEvent& event);
    bool Pop(UIEvent& event);

private:
    std::queue<UIEvent> m_queue;
};