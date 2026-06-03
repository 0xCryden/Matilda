#pragma once

enum class UICommand
{
    None,
    ButtonClicked,
};

struct UIEvent
{
    UICommand m_command = UICommand::None;
    int m_targetId = -1;
};