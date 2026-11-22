#pragma once
#include <windows.h>
#include <bit>
#include <cwchar>

namespace proton_needle_fixture
{
// DLL fixtures must be harmless if someone accidentally loads them outside the
// exact live fixture target. In particular, never ExitProcess an application.
inline bool fixture_context()
{
    wchar_t session[33]{}, instance[33]{}, image[32768]{}, event[160]{};
    if (GetEnvironmentVariableW(L"PROTON_NEEDLE_FIXTURE_SESSION", session, 33) != 32 ||
        GetEnvironmentVariableW(L"PROTON_NEEDLE_TEST_INSTANCE", instance, 33) != 32)
        return false;
    for (unsigned index = 0; index != 32; ++index)
        if (!((session[index] >= L'0' && session[index] <= L'9') ||
              (session[index] >= L'a' && session[index] <= L'f')) ||
            !((instance[index] >= L'0' && instance[index] <= L'9') ||
              (instance[index] >= L'a' && instance[index] <= L'f')))
            return false;
    const DWORD length = GetModuleFileNameW(nullptr, image, 32768);
    if (!length || length >= 32768)
        return false;
    const wchar_t *name = std::wcsrchr(image, L'\\');
    name = name ? name + 1 : image;
    if (std::wcscmp(name, L"proton_needle_test_target.exe") != 0)
        return false;
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user))
        return false;
    const auto ticks =
        (static_cast<unsigned long long>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    if (std::swprintf(event, 160, L"Local\\ProtonNeedleFixture_%ls_%ls_%lu_%llu", session, instance,
                      GetCurrentProcessId(), ticks) <= 0)
        return false;
    const HANDLE proof = OpenEventW(SYNCHRONIZE, FALSE, event);
    if (!proof)
        return false;
    const bool valid = WaitForSingleObject(proof, 0) == WAIT_OBJECT_0;
    CloseHandle(proof);
    return valid;
}
} // namespace proton_needle_fixture

namespace proton_needle_fixture
{
class environment_path
{
  public:
    explicit environment_path(const wchar_t *name)
    {
        const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
        if (!size || size > 32768)
        {
            return;
        }
        value_ = static_cast<wchar_t *>(HeapAlloc(GetProcessHeap(), 0, size * sizeof(wchar_t)));
        if (!value_)
        {
            return;
        }
        const DWORD length = GetEnvironmentVariableW(name, value_, size);
        if (!length || length >= size)
        {
            clear();
            return;
        }
        if (value_[0] != L'/')
        {
            return;
        }
        using map_path_fn = wchar_t *(__cdecl *)(const char *);
        const auto map_path = std::bit_cast<map_path_fn>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "wine_get_dos_file_name"));
        const int utf8_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value_, -1,
                                                  nullptr, 0, nullptr, nullptr);
        if (!map_path || utf8_size <= 0)
        {
            clear();
            return;
        }
        auto utf8 =
            static_cast<char *>(HeapAlloc(GetProcessHeap(), 0, static_cast<SIZE_T>(utf8_size)));
        if (!utf8)
        {
            clear();
            return;
        }
        wchar_t *mapped = nullptr;
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value_, -1, utf8, utf8_size, nullptr,
                                nullptr) == utf8_size)
        {
            mapped = map_path(utf8);
        }
        HeapFree(GetProcessHeap(), 0, utf8);
        clear();
        value_ = mapped;
    }

    ~environment_path()
    {
        clear();
    }

    environment_path(const environment_path &) = delete;
    environment_path &operator=(const environment_path &) = delete;

    const wchar_t *get() const noexcept
    {
        return value_;
    }

  private:
    void clear() noexcept
    {
        if (value_)
        {
            HeapFree(GetProcessHeap(), 0, value_);
            value_ = nullptr;
        }
    }

    wchar_t *value_ = nullptr;
};

inline bool write_pid_file(const wchar_t *path)
{
    if (!path)
    {
        return false;
    }
    const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    char text[16]{};
    char reversed[10]{};
    DWORD pid = GetCurrentProcessId();
    DWORD digits = 0;
    do
    {
        reversed[digits++] = static_cast<char>('0' + pid % 10);
        pid /= 10;
    } while (pid);
    for (DWORD index = 0; index < digits; ++index)
    {
        text[index] = reversed[digits - index - 1];
    }
    text[digits++] = '\n';
    DWORD written = 0;
    const bool success = WriteFile(file, text, digits, &written, nullptr) && written == digits;
    CloseHandle(file);
    return success;
}
} // namespace proton_needle_fixture
