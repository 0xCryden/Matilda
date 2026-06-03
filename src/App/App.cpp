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
		WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU,
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
		// TODO: remove InvalidateRect calls and replace with track dirty regions (for now, just redraw everything)
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);

		if (!m_memDC)
		{
			EndPaint(hwnd, &ps);
			return 0;
		}

		RECT clientRect;
		GetClientRect(hwnd, &clientRect);

		const int width = clientRect.right - clientRect.left;
		const int height = clientRect.bottom - clientRect.top;

		// -----------------------------
		// 1. Background brush (reuse later ideally)
		// -----------------------------
		HBRUSH bgBrush = CreateSolidBrush(RGB(25, 25, 25));

		// -----------------------------
		// 2. Determine redraw strategy
		// -----------------------------
		bool fullRedraw = m_dirtyRegions.empty();

		if (fullRedraw)
		{
			// FULL CLEAR (initial load / resize fallback)
			FillRect(m_memDC, &clientRect, bgBrush);
		}
		else
		{
			// PARTIAL CLEAR (only dirty regions)
			for (const RECT& r : m_dirtyRegions)
			{
				FillRect(m_memDC, &r, bgBrush);
			}
		}

		DeleteObject(bgBrush);

		// -----------------------------
		// 3. Draw UI into backbuffer
		// -----------------------------
		m_window->Draw(m_memDC, m_themeManager.GetTheme());

		// -----------------------------
		// 4. Blit to screen
		// -----------------------------
		BitBlt(
			hdc,
			0, 0,
			width, height,
			m_memDC,
			0, 0,
			SRCCOPY
		);

		// -----------------------------
		// 5. Clear dirty regions AFTER render
		// -----------------------------
		m_dirtyRegions.clear();

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

	case WM_SIZE:
	{
		int w = LOWORD(lParam);
		int h = HIWORD(lParam);

		ResizeBackBuffer(w, h);
		
		// TODO: other elements need resizing too (not just main window)
		if (m_window)
			m_window->SetSize(w, h);

		InvalidateRect(hwnd, nullptr, FALSE);

		return 0;
	}

	case WM_NCCALCSIZE:
	{
		if (wParam)
			return 0;

		break;
	}
	case WM_NCPAINT:
		return 0;
	case WM_NCACTIVATE:
		return TRUE;
	}

	return DefWindowProc(
		hwnd,
		msg,
		wParam,
		lParam);
}

void App::InvalidateUIRect(const RECT& r)
{
	InvalidateRect(m_hwnd, &r, FALSE);
}

void App::AddDirtyRect(const RECT& r)
{
	m_dirtyRegions.push_back(r);
}

void App::ResizeBackBuffer(int w, int h)
{
	if (m_memDC)
	{
		DeleteObject(m_memBitmap);
		DeleteDC(m_memDC);
	}

	HDC hdc = GetDC(m_hwnd);

	m_memDC = CreateCompatibleDC(hdc);
	m_memBitmap = CreateCompatibleBitmap(hdc, w, h);
	SelectObject(m_memDC, m_memBitmap);

	ReleaseDC(m_hwnd, hdc);

	m_backW = w;
	m_backH = h;
}