#pragma once
#include "../UI/UIEvent.h"

class AppController
{
public:
    void HandleEvent(const UIEvent& e);

private:
    void Play();
    void Settings();
};