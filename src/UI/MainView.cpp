#include "MainView.h"
#include "Components/UIWindow.h"
#include "Components/UITitlebar.h"
#include "Components/UIButton.h"
#include "../Utils/Constants.h"

MainView::MainView(UIWindow* window, AppController*)
{
    window->AddChild(new UITitlebar(0, 0, Constants::DefaultWindowWidth, Constants::TitlebarHeight, 1, window));

    window->AddChild(new UIButton(50, 50, 120, 40, 2, L"Play"));
    window->AddChild(new UIButton(50, 100, 120, 40, 3, L"Settings"));
}