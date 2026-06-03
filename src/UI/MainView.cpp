#include "MainView.h"
#include "UIWindow.h"
#include "Components/UIButton.h"

MainView::MainView(UIWindow* window, AppController*)
{
    window->AddChild(new UIButton(50, 50, 120, 40, 1, L"Play"));
    window->AddChild(new UIButton(50, 100, 120, 40, 2, L"Settings"));
}