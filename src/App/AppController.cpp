#include "AppController.h"
#include <windows.h>

void AppController::HandleEvent(const UIEvent& e)
{
    if (e.m_command != UICommand::ButtonClicked)
        return;

    switch (e.m_targetId)
    {
    case 2: Play(); break;
    case 3: Settings(); break;
    }
}

void AppController::Play()
{
    MessageBoxW(nullptr, L"Play", L"App", MB_OK);
}

void AppController::Settings()
{
    MessageBoxW(nullptr, L"Settings", L"App", MB_OK);
}