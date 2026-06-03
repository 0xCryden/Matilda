#pragma once
#include "UITheme.h"

enum class ThemeType
{
    Light,
    Dark
};

class ThemeManager
{
public:
    ThemeManager();
    ~ThemeManager();

    void SetTheme(ThemeType type);

    UITheme* GetTheme() const;

private:
    UITheme* m_currentTheme = nullptr;
};