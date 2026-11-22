#include "environment_path.hpp"

extern "C" __declspec(dllexport) DWORD proton_needle_fixture_pid()
{
    return GetCurrentProcessId();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        if (!proton_needle_fixture::fixture_context())
            return FALSE;
        // Keep CRT thread notifications enabled: fixtures link the static runtime.
        // Deliberately only existing-module lookup, process-heap allocation and one minimal file
        // write. No threads, waits, library loads or application calls are made while holding the
        // loader lock.
        proton_needle_fixture::environment_path marker(L"PROTON_NEEDLE_TEST_MARKER");
        if (!proton_needle_fixture::write_pid_file(marker.get()))
        {
            return FALSE;
        }
    }
    return TRUE;
}
