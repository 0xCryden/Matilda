// Matilda.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "Matilda.h"

#include <iostream>
#include <thread>
#include <atomic>
#include <sstream>
#include <chrono>

#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"

#include "Packet.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IPv4Layer.h"

#define MAX_LOADSTRING 100


std::thread g_captureThread;
std::atomic<bool> g_running(false);
HWND g_outputBox = nullptr;
HWND g_mainWindow = nullptr;

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

void AppendText(HWND hEdit, const std::string& text)
{
	int len = GetWindowTextLengthA(hEdit);
	SendMessageA(hEdit, EM_SETSEL, len, len);
	SendMessageA(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
}

int subMain()
{
	auto& devList = pcpp::PcapLiveDeviceList::getInstance();
	auto devices = devList.getPcapLiveDevicesList();

	if (devices.empty())
	{
		std::string msg = "No capture devices found\r\n";
		PostMessageA(g_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string(msg));
		return 1;
	}

	pcpp::PcapLiveDevice* dev = devices[0];

	if (!dev->open())
	{
		std::string msg = "Failed to open device\r\n";
		PostMessageA(g_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string(msg));
		return 1;
	}

	g_running = true;

	dev->startCapture(
		[](pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice*, void*)
		{
			if (!g_running)
				return;

			pcpp::Packet packet(rawPacket);

			std::ostringstream out;

			auto ip = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (ip)
			{
				out << "IP: "
					<< ip->getSrcIPAddress().toString()
					<< " -> "
					<< ip->getDstIPAddress().toString()
					<< "\r\n";
			}

			auto tcp = packet.getLayerOfType<pcpp::TcpLayer>();
			if (tcp)
			{
				auto h = tcp->getTcpHeader();
				out << "TCP SEQ: " << ntohl(h->sequenceNumber)
					<< " ACK: " << ntohl(h->ackNumber)
					<< "\r\n";
			}

			out << "---------------------\r\n";

			std::string text = out.str();

			// send to UI safely
			PostMessageA(g_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string(text));
		},
		nullptr
	);

	while (g_running)
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

	dev->stopCapture();
	dev->close();

	return 0;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// TODO: Place code here.
	// 
	// Initialize global strings
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadStringW(hInstance, IDC_MATILDA, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}



	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MATILDA));

	MSG msg;

	// Main message loop:
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MATILDA));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_MATILDA);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance; // Store instance handle in our global variable

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, 800, 600, nullptr, nullptr, hInstance, nullptr);

	g_mainWindow = hWnd;

	g_outputBox = CreateWindowA("EDIT", "",
		WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
		10, 10, 760, 450,
		hWnd, nullptr, hInstance, nullptr);

	CreateWindowA("BUTTON", "Start Capture",
		WS_CHILD | WS_VISIBLE,
		10, 480, 120, 30,
		hWnd, (HMENU)1, hInstance, nullptr);

	CreateWindowA("BUTTON", "Stop Capture",
		WS_CHILD | WS_VISIBLE,
		140, 480, 120, 30,
		hWnd, (HMENU)2, hInstance, nullptr);

	if (!hWnd)
	{
		return FALSE;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);
	SetFocus(g_outputBox);
	// initial status
	PostMessageA(g_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string("Application started\r\n"));

	return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case 1: // Start
			if (!g_running)
			{
				PostMessageA(g_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string("Starting capture...\r\n"));
				g_captureThread = std::thread([]()
					{
						subMain();
					});
			}
			break;

		case 2: // Stop
			g_running = false;
			PostMessageA(g_mainWindow, WM_APP + 1, 0, (LPARAM)new std::string("Stopping capture...\r\n"));
			break;
		}
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code that uses hdc here...
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_APP + 1:
	{
		std::string* text = (std::string*)lParam;
		AppendText(g_outputBox, *text);
		delete text;
		break;
	}
	case WM_DESTROY:
	{
		g_running = false;

		if (g_captureThread.joinable())
			g_captureThread.join();

		PostQuitMessage(0);
	}
	break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}