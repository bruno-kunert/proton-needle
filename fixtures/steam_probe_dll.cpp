#include <windows.h>
#include <cwchar>

namespace
{
DWORD attached_pid = 0;

bool expected_host()
{
    wchar_t image[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, image, 32768);
    if (!length || length >= 32768)
        return false;
    const wchar_t *name = std::wcsrchr(image, L'\\');
    name = name ? name + 1 : image;
    return _wcsicmp(name, L"proton_needle_steam_target.exe") == 0;
}
}

extern "C" __declspec(dllexport) DWORD proton_needle_steam_probe_pid()
{
    return attached_pid;
}

extern "C" __declspec(dllexport) DWORD proton_needle_steam_probe_version()
{
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        if (!expected_host())
            return FALSE;
        attached_pid = GetCurrentProcessId();
    }
    return TRUE;
}
