#pragma once

#include <windows.h>

#include "../UI/Components/UIWindow.h"
#include "../UI/UIEventQueue.h"
#include "../UI/ThemeManager.h"
#include "AppController.h"

class App
{
public:
    App(HINSTANCE hInstance);
    ~App();

    int Run(int nCmdShow);

    LRESULT HandleMessage(
        HWND hwnd,
        UINT msg,
        WPARAM wParam,
        LPARAM lParam);

private:
    bool InitWindow(int nCmdShow);
    void BuildUI();

private:
    HINSTANCE m_hInstance = nullptr;

    HWND m_hwnd = nullptr;

    UIWindow* m_window = nullptr;

    UIEventQueue m_eventQueue;
    AppController m_controller;
    ThemeManager m_themeManager;
};