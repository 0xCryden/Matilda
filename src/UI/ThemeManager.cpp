#include "ThemeManager.h"
#include "Themes/ThemeDark.h"
#include "Themes/ThemeLight.h"
// #include "DarkTheme.h" (later)

ThemeManager::ThemeManager()
{
    m_currentTheme = new ThemeDark();
}

ThemeManager::~ThemeManager()
{
    delete m_currentTheme;
}

void ThemeManager::SetTheme(ThemeType type)
{
    delete m_currentTheme;

    switch (type)
    {
    case ThemeType::Dark:
        m_currentTheme = new ThemeDark(); // placeholder
        break;

    case ThemeType::Light:
        m_currentTheme = new ThemeLight();
        break;
    }
}

UITheme* ThemeManager::GetTheme() const
{
    return m_currentTheme;
}