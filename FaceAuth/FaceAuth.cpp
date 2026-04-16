#include <windows.h>

#include <iterator>
#include <iostream>
#include <sstream>
#include <string>

int main()
{
    const HWND foregroundWindow = GetForegroundWindow();
    wchar_t windowTitle[256]{};

    if (foregroundWindow != nullptr)
    {
        GetWindowTextW(foregroundWindow, windowTitle, static_cast<int>(std::size(windowTitle)));
    }

    const int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    const int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    SYSTEMTIME localTime{};
    GetLocalTime(&localTime);

    std::wstringstream message;
    message << L"Win32 API demo\n\n"
            << L"Foreground window title: "
            << (windowTitle[0] != L'\0' ? windowTitle : L"(none)")
            << L"\nScreen size: " << screenWidth << L"x" << screenHeight
            << L"\nLocal time: "
            << localTime.wHour << L":"
            << (localTime.wMinute < 10 ? L"0" : L"") << localTime.wMinute;

    MessageBoxW(nullptr, message.str().c_str(), L"FaceAuth Win32 Demo", MB_OK | MB_ICONINFORMATION);

    std::wcout << L"Message box displayed using the Win32 API.\n";
    std::wcout << L"Screen size reported by GetSystemMetrics: "
               << screenWidth << L"x" << screenHeight << L"\n";

    if (windowTitle[0] != L'\0')
    {
        std::wcout << L"Foreground window title: " << windowTitle << L"\n";
    }
    else
    {
        std::wcout << L"No foreground window title was available.\n";
    }

    return 0;
}
