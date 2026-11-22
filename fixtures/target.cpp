#include "environment_path.hpp"
#include <cstdio>
#include <memory>
#include <string>

namespace
{
bool write_readiness(const wchar_t *path, const wchar_t *session, const wchar_t *instance,
                     ULONGLONG creation)
{
    wchar_t image[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, image, 32768);
    if (!length || length >= 32768)
        return false;
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, image,
                                          static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0)
        return false;
    std::string utf8(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, image, static_cast<int>(length),
                            utf8.data(), bytes, nullptr, nullptr) != bytes)
        return false;
    std::string token;
    for (const wchar_t *p = session; *p; ++p)
        token.push_back(static_cast<char>(*p));
    std::string instance_token;
    for (const wchar_t *p = instance; *p; ++p)
        instance_token.push_back(static_cast<char>(*p));
    const auto contents = std::to_string(GetCurrentProcessId()) + "\n" + token + "\n" +
                          std::to_string(creation) + "\n" + utf8 + "\n" + instance_token + "\n";
    const HANDLE file =
        CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    const bool success =
        WriteFile(file, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) &&
        written == contents.size() && FlushFileBuffers(file);
    CloseHandle(file);
    return success;
}
} // namespace

int main()
{
    using namespace proton_needle_fixture;
    wchar_t session[33]{}, instance[33]{};
    if (GetEnvironmentVariableW(L"PROTON_NEEDLE_FIXTURE_SESSION", session, 33) != 32 ||
        std::wstring(session).find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
        GetEnvironmentVariableW(L"PROTON_NEEDLE_TEST_INSTANCE", instance, 33) != 32 ||
        std::wstring(instance).find_first_not_of(L"0123456789abcdef") != std::wstring::npos)
        return 1;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 1;
    const ULONGLONG creation =
        (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    const auto proof_name = L"Local\\ProtonNeedleFixture_" + std::wstring(session) + L"_" +
                            std::wstring(instance) + L"_" + std::to_wstring(GetCurrentProcessId()) +
                            L"_" + std::to_wstring(creation);
    std::unique_ptr<void, decltype(&CloseHandle)> proof(
        CreateEventW(nullptr, TRUE, TRUE, proof_name.c_str()), &CloseHandle);
    if (!proof || GetLastError() == ERROR_ALREADY_EXISTS)
        return 1;
    wchar_t stop_event_name[256]{};
    const DWORD configured_length =
        GetEnvironmentVariableW(L"PROTON_NEEDLE_TEST_STOP_EVENT", stop_event_name, 256);
    if (configured_length >= 256)
    {
        std::fputs("PROTON_NEEDLE_TEST_STOP_EVENT is too long\n", stderr);
        return 1;
    }
    if (!configured_length)
    {
        // Decimal conversion avoids locale-sensitive CRT formatting and fixes the cleanup event
        // contract.
        wchar_t reversed[10]{};
        DWORD pid = GetCurrentProcessId();
        DWORD digits = 0;
        do
        {
            reversed[digits++] = static_cast<wchar_t>(L'0' + pid % 10);
            pid /= 10;
        } while (pid);
        constexpr wchar_t prefix[] = L"Local\\ProtonNeedleTestStop_";
        DWORD prefix_length = 0;
        while (prefix[prefix_length])
        {
            stop_event_name[prefix_length] = prefix[prefix_length];
            ++prefix_length;
        }
        for (DWORD index = 0; index < digits; ++index)
        {
            stop_event_name[prefix_length + index] = reversed[digits - index - 1];
        }
    }
    const HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, stop_event_name);
    if (!stop_event)
    {
        std::fprintf(stderr, "Could not create cleanup event: %lu\n", GetLastError());
        return 1;
    }
    wchar_t gate_name[256]{};
    const DWORD gate_length =
        GetEnvironmentVariableW(L"PROTON_NEEDLE_TEST_GATE_EVENT", gate_name, 256);
    std::unique_ptr<void, decltype(&CloseHandle)> gate_event(nullptr, &CloseHandle);
    if (gate_length)
    {
        if (gate_length < 256)
        {
            gate_event.reset(CreateEventW(nullptr, TRUE, FALSE, gate_name));
        }
        if (!gate_event)
        {
            CloseHandle(stop_event);
            return 1;
        }
    }
    environment_path gate_release(L"PROTON_NEEDLE_TEST_GATE_RELEASE");
    environment_path ready_path(L"PROTON_NEEDLE_TEST_READY");
    environment_path stop_path(L"PROTON_NEEDLE_TEST_STOP");
    environment_path interrupted(L"PROTON_NEEDLE_TEST_INTERRUPT");
    if (!ready_path.get() || !write_readiness(ready_path.get(), session, instance, creation))
    {
        std::fprintf(stderr,
                     "PROTON_NEEDLE_TEST_READY must identify a writable readiness file: %lu\n",
                     GetLastError());
        CloseHandle(stop_event);
        return 1;
    }
    int result = 0;
    const ULONGLONG deadline = GetTickCount64() + 300000;
    for (;;)
    {
        // Root-local interruption stops only this self-built target. The hard
        // lifetime also covers a runner killed before it could write the marker.
        if (GetTickCount64() >= deadline ||
            (interrupted.get() && GetFileAttributesW(interrupted.get()) != INVALID_FILE_ATTRIBUTES))
            break;
        const DWORD state = WaitForSingleObject(stop_event, 100);
        if (state == WAIT_OBJECT_0)
        {
            break;
        }
        if (state != WAIT_TIMEOUT)
        {
            result = 1;
            break;
        }
        if (gate_event && gate_release.get() &&
            GetFileAttributesW(gate_release.get()) != INVALID_FILE_ATTRIBUTES)
        {
            SetEvent(gate_event.get());
        }
        if (stop_path.get() && GetFileAttributesW(stop_path.get()) != INVALID_FILE_ATTRIBUTES)
        {
            break;
        }
    }
    CloseHandle(stop_event);
    return result;
}
