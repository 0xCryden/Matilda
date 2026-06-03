#pragma once

#include <windows.h>

namespace UI {

// Enable a frameless client-drawn window chrome. headbarHeight is the height
// in pixels (from the top of client area) that will act as a draggable caption.
// This installs a window subclass to handle WM_NCHITTEST and WM_NCCALCSIZE.
bool EnableFrameless(HWND hwnd, int headbarHeight);

} // namespace UI
