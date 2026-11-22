#include "environment_path.hpp"

// This fixture deliberately exercises loader failure paths.
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH)
    {
        return TRUE;
    }
    if (!proton_needle_fixture::fixture_context())
        return FALSE;
#if defined(PROTON_NEEDLE_FIXTURE_REJECT)
    proton_needle_fixture::environment_path marker(L"PROTON_NEEDLE_TEST_MARKER");
    proton_needle_fixture::write_pid_file(marker.get());
    return FALSE;
#elif defined(PROTON_NEEDLE_FIXTURE_EXIT)
    ExitProcess(86);
    return FALSE;
#else
    wchar_t event_name[256]{};
    const DWORD length = GetEnvironmentVariableW(L"PROTON_NEEDLE_TEST_GATE_EVENT", event_name, 256);
    if (!length || length >= 256)
    {
        return FALSE;
    }
    const HANDLE gate = OpenEventW(SYNCHRONIZE, FALSE, event_name);
    if (!gate)
    {
        return FALSE;
    }
    proton_needle_fixture::environment_path entered(L"PROTON_NEEDLE_TEST_GATE_ENTERED");
    if (!proton_needle_fixture::write_pid_file(entered.get()))
    {
        CloseHandle(gate);
        return FALSE;
    }
    const DWORD state = WaitForSingleObject(gate, 20000);
    CloseHandle(gate);
    if (state != WAIT_OBJECT_0)
    {
        return FALSE;
    }
    proton_needle_fixture::environment_path marker(L"PROTON_NEEDLE_TEST_MARKER");
    return proton_needle_fixture::write_pid_file(marker.get()) ? TRUE : FALSE;
#endif
}
