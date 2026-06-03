#include "App/App.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow)
{
    App app(hInstance);
    return app.Run(nCmdShow);
}