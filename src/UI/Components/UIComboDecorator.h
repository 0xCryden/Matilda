#pragma once

#include <windows.h>

namespace UI {

class UIComboDecorator {
public:
    // Install decorator subclass on combo box
    static bool Install(HWND combo);

private:
    static LRESULT CALLBACK ComboSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
        UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
};

} // namespace UI
