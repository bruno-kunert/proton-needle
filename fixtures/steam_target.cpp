#include <windows.h>
#include <cstring>
#include <string>

namespace
{
constexpr wchar_t probe_name[] = L"proton_needle_steam_probe.dll";
constexpr UINT_PTR refresh_timer = 1;

using probe_pid_fn = DWORD(__cdecl *)();

ULONGLONG creation_ticks()
{
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 0;
    return (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

std::wstring image_path()
{
    std::wstring image(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, image.data(), 32768);
    image.resize(length < 32768 ? length : 0);
    return image;
}

std::wstring wine_version()
{
    using wine_get_version_fn = const char *(__cdecl *)();
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto get = ntdll ? reinterpret_cast<wine_get_version_fn>(reinterpret_cast<void *>(
                                 GetProcAddress(ntdll, "wine_get_version")))
                           : nullptr;
    if (!get)
        return L"not reported (not Wine/Proton?)";
    std::wstring result;
    for (const char *p = get(); p && *p; ++p)
        result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*p)));
    return result;
}

DWORD probe_pid(HMODULE probe)
{
    if (!probe)
        return 0;
    const auto get = reinterpret_cast<probe_pid_fn>(
        reinterpret_cast<void *>(GetProcAddress(probe, "proton_needle_steam_probe_pid")));
    return get ? get() : 0;
}

std::wstring status_text()
{
    const DWORD pid = GetCurrentProcessId();
    std::wstring text = L"ProtonNeedle Steam/Proton test target\r\n\r\n";
    text += L"Windows PID: " + std::to_wstring(pid) + L"\r\n";
    text += L"Creation time (FILETIME): " + std::to_wstring(creation_ticks()) + L"\r\n";
    text += L"Image: " + image_path() + L"\r\n";
    text += L"Wine version: " + wine_version() + L"\r\n\r\n";
    const HMODULE probe = GetModuleHandleW(probe_name);
    if (!probe)
    {
        text += L"Probe DLL: not loaded";
    }
    else
    {
        const DWORD reported = probe_pid(probe);
        text += L"Probe DLL: LOADED, reports PID " + std::to_wstring(reported) +
                (reported == pid ? L" (matches)" : L" (MISMATCH)");
    }
    text += L"\r\n\r\nClose this window to exit.";
    return text;
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message)
    {
    case WM_TIMER:
        InvalidateRect(window, nullptr, TRUE);
        return 0;
    case WM_PAINT:
    {
        PAINTSTRUCT paint{};
        const HDC dc = BeginPaint(window, &paint);
        RECT area{};
        GetClientRect(window, &area);
        InflateRect(&area, -12, -12);
        const auto text = status_text();
        DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &area,
                  DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
        EndPaint(window, &paint);
        return 0;
    }
    case WM_DESTROY:
        KillTimer(window, refresh_timer);
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

int self_test()
{
    auto path = image_path();
    const auto separator = path.find_last_of(L'\\');
    if (path.empty() || separator == std::wstring::npos)
        return 2;
    path.resize(separator + 1);
    path += probe_name;
    if (GetModuleHandleW(probe_name))
        return 3;
    const HMODULE probe = LoadLibraryW(path.c_str());
    if (!probe)
        return 4;
    const bool matches = probe_pid(probe) == GetCurrentProcessId();
    FreeLibrary(probe);
    return matches ? 0 : 5;
}
} // namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR command_line, int show)
{
    if (command_line && std::strcmp(command_line, "--self-test") == 0)
        return self_test();
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    window_class.lpszClassName = L"ProtonNeedleSteamTestTarget";
    if (!RegisterClassExW(&window_class))
        return 1;
    const HWND window =
        CreateWindowExW(0, window_class.lpszClassName, L"ProtonNeedle Steam/Proton Test Target",
                        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 720, 320, nullptr,
                        nullptr, instance, nullptr);
    if (!window || !SetTimer(window, refresh_timer, 500, nullptr))
        return 1;
    ShowWindow(window, show);
    UpdateWindow(window);
    MSG message{};
    BOOL result = 0;
    while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return result < 0 ? 1 : static_cast<int>(message.wParam);
}
