#include "App.h"
#include "../UI/MainView.h"
#include <windowsx.h>
#include "../Utils/Constants.h"
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

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
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = Constants::MainWindowClass;

    RegisterClass(&wc);

    m_hwnd = CreateWindowEx(
        0,
        Constants::MainWindowClass,
        Constants::AppName,
        WS_POPUP | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        Constants::DefaultWindowWidth, Constants::DefaultWindowHeight,
        nullptr,
        nullptr,
        m_hInstance,
        this
    );

    if (!m_hwnd)
        return false;

    SetWindowText(m_hwnd, Constants::AppName);

    HICON icon = (HICON)LoadImage(
        m_hInstance,
        MAKEINTRESOURCE(IDI_APPLICATION), // or your custom icon
        IMAGE_ICON,
        32, 32,
        LR_DEFAULTCOLOR
    );

    SendMessage(m_hwnd, WM_SETICON, ICON_BIG, (LPARAM)icon);
    SendMessage(m_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)icon);

    BOOL value = TRUE;
    DwmSetWindowAttribute(
        m_hwnd,
        DWMWA_NCRENDERING_ENABLED,
        &value,
        sizeof(value)
    );

    //MARGINS margins = { -1 };
    //DwmExtendFrameIntoClientArea(m_hwnd, &margins);

    ShowWindow(m_hwnd, nCmdShow);

    m_window = new UIWindow(m_hwnd);
    m_window->SetSize(Constants::DefaultWindowWidth, Constants::DefaultWindowHeight);

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
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);

        int width = rc.right - rc.left;
        int height = rc.bottom - rc.top;

        // 1. Create back buffer
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBitmap = CreateCompatibleBitmap(hdc, width, height);
        HGDIOBJ oldBitmap = SelectObject(memDC, memBitmap);

        // 2. Clear background (important!)
        HBRUSH bg = CreateSolidBrush(RGB(25, 25, 25));
        FillRect(memDC, &rc, bg);
        DeleteObject(bg);

        // 3. Draw everything into back buffer
        m_window->Draw(memDC, m_themeManager.GetTheme());

        // 4. Blit to screen in one go
        BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);

        // 5. Cleanup
        SelectObject(memDC, oldBitmap);
        DeleteObject(memBitmap);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    /*case WM_PAINT:
    {
        PAINTSTRUCT ps;

        HDC hdc =
            BeginPaint(hwnd, &ps);

        m_window->Draw(
            hdc,
            m_themeManager.GetTheme());

        EndPaint(hwnd, &ps);

        return 0;
    }*/

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

    case WM_LBUTTONUP:
    {
        int x = GET_X_LPARAM(lParam);
        int y = GET_Y_LPARAM(lParam);

        m_window->OnMouseUp(
            x,
            y,
            m_eventQueue);
        return 0;
    }

    case WM_MOUSEMOVE:
    {
        int x = GET_X_LPARAM(lParam);
        int y = GET_Y_LPARAM(lParam);

        m_window->OnMouseMove(x, y);
        return 0;
    }

    case WM_DESTROY:
    {
        PostQuitMessage(0);
        return 0;
    }
    
    case WM_NCHITTEST:
    {
        const int border = Constants::WindowBorderThickness;

        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);

        RECT rc;
        GetClientRect(hwnd, &rc);

        bool left = pt.x < border;
        bool right = pt.x > rc.right - border;
        bool top = pt.y < border;
        bool bottom = pt.y > rc.bottom - border;

        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;

        return HTCLIENT;
    }
    
    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;

        mmi->ptMinTrackSize.x = 400;
        mmi->ptMinTrackSize.y = 300;

        return 0;
    }
    }

    return DefWindowProc(
        hwnd,
        msg,
        wParam,
        lParam);
}