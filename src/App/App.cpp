#include "App.h"
#include "../UI/MainView.h"
#include <windowsx.h>

namespace
{
    LRESULT CALLBACK WndProc(
        HWND hwnd,
        UINT msg,
        WPARAM wParam,
        LPARAM lParam)
    {
        if (msg == WM_NCCREATE)
        {
            CREATESTRUCT* cs =
                reinterpret_cast<CREATESTRUCT*>(lParam);

            App* app =
                static_cast<App*>(cs->lpCreateParams);

            SetWindowLongPtr(
                hwnd,
                GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(app));

            return TRUE;
        }

        App* app =
            reinterpret_cast<App*>(
                GetWindowLongPtr(hwnd, GWLP_USERDATA));

        if (app)
        {
            return app->HandleMessage(
                hwnd,
                msg,
                wParam,
                lParam);
        }

        return DefWindowProc(
            hwnd,
            msg,
            wParam,
            lParam);
    }
}

App::App(HINSTANCE hInstance)
    : m_hInstance(hInstance)
{
    // default configuration lives HERE (not in main)
    m_themeManager.SetTheme(ThemeType::Dark);
}

App::~App()
{
    delete m_window;
}

int App::Run(int nCmdShow)
{
    if (!InitWindow(nCmdShow))
        return -1;

    BuildUI();

    MSG msg = {};

    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        // EVENT DISPATCH (UI -> Controller)
        UIEvent e;
        while (m_eventQueue.Pop(e))
        {
            m_controller.HandleEvent(e);
        }
    }

    return (int)msg.wParam;
}

bool App::InitWindow(int nCmdShow)
{
    const wchar_t CLASS_NAME[] = L"MyAppWindow";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    m_hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"UI Tool",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 600,
        nullptr,
        nullptr,
        m_hInstance,
        this
    );

    if (!m_hwnd)
        return false;

    ShowWindow(m_hwnd, nCmdShow);

    m_window = new UIWindow(m_hwnd);
    m_window->SetSize(900, 600);

    return true;
}

void App::BuildUI()
{
    MainView view(m_window, &m_controller);
}

LRESULT App::HandleMessage(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;

        HDC hdc =
            BeginPaint(hwnd, &ps);

        m_window->Draw(
            hdc,
            m_themeManager.GetTheme());

        EndPaint(hwnd, &ps);

        return 0;
    }

    case WM_LBUTTONDOWN:
    {
        int x = GET_X_LPARAM(lParam);
        int y = GET_Y_LPARAM(lParam);

        m_window->OnMouseDown(
            x,
            y,
            m_eventQueue);

        InvalidateRect(
            hwnd,
            nullptr,
            TRUE);

        return 0;
    }

    case WM_MOUSEMOVE:
    {
        int x = GET_X_LPARAM(lParam);
        int y = GET_Y_LPARAM(lParam);

        m_window->OnMouseMove(x, y);

        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_DESTROY:
    {
        PostQuitMessage(0);
        return 0;
    }
    }

    return DefWindowProc(
        hwnd,
        msg,
        wParam,
        lParam);
}