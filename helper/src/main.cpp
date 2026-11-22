#include <windows.h>
#include <nlohmann/json.hpp>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
using json = nlohmann::json;
constexpr std::size_t maximum_request_size = 65536;
constexpr std::size_t maximum_path_size = 32768;
struct heap_deleter
{
    void operator()(void *allocation) const noexcept
    {
        HeapFree(GetProcessHeap(), 0, allocation);
    }
};

class failure : public std::runtime_error
{
  public:
    failure(std::string error_code, std::string message, DWORD native_error = 0,
            bool unknown_outcome = false)
        : std::runtime_error(std::move(message)), code(std::move(error_code)),
          system_error(native_error), inconclusive(unknown_outcome)
    {
    }

    std::string code;
    DWORD system_error;
    bool inconclusive;
};

[[noreturn]] void fail_windows(const char *code, const char *message, bool unknown_outcome = false)
{
    throw failure(code, message, GetLastError(), unknown_outcome);
}

class unique_handle
{
  public:
    explicit unique_handle(HANDLE value = nullptr) noexcept : value_(value)
    {
    }

    ~unique_handle()
    {
        if (value_ && value_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(value_);
        }
    }

    unique_handle(const unique_handle &) = delete;
    unique_handle &operator=(const unique_handle &) = delete;

    HANDLE get() const noexcept
    {
        return value_;
    }

    explicit operator bool() const noexcept
    {
        return value_ && value_ != INVALID_HANDLE_VALUE;
    }

  private:
    HANDLE value_;
};

class remote_buffer
{
  public:
    remote_buffer(HANDLE process, std::size_t size) : process_(process)
    {
        address_ = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!address_)
        {
            fail_windows("allocation_failed", "Could not allocate the remote DLL path");
        }
    }

    ~remote_buffer()
    {
        if (!retain_)
        {
            VirtualFreeEx(process_, address_, 0, MEM_RELEASE);
        }
    }

    remote_buffer(const remote_buffer &) = delete;
    remote_buffer &operator=(const remote_buffer &) = delete;

    void *get() const noexcept
    {
        return address_;
    }

    void retain() noexcept
    {
        retain_ = true;
    }

  private:
    HANDLE process_;
    void *address_ = nullptr;
    bool retain_ = false;
};

std::wstring from_utf8(const std::string &text)
{
    if (text.empty() || text.find('\0') != std::string::npos || text.size() > maximum_path_size)
    {
        throw failure("invalid_path", "Paths must be nonempty, bounded UTF-8 without NUL bytes");
    }
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0)
    {
        fail_windows("invalid_utf8", "Path is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), size) != size)
    {
        fail_windows("invalid_utf8", "Could not decode UTF-8 path");
    }
    return result;
}

std::string to_utf8(const std::wstring &text)
{
    if (text.empty())
    {
        return {};
    }
    const int size =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0)
    {
        fail_windows("invalid_unicode", "Could not encode a Windows path as UTF-8");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), size, nullptr,
                            nullptr) != size)
    {
        fail_windows("invalid_unicode", "Could not encode a Windows path as UTF-8");
    }
    return result;
}

std::wstring full_path(const std::wstring &path)
{
    const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (size == 0 || size > maximum_path_size)
    {
        fail_windows("invalid_path", "Could not canonicalize Windows path");
    }
    std::wstring result(size, L'\0');
    const DWORD length = GetFullPathNameW(path.c_str(), size, result.data(), nullptr);
    if (length == 0 || length >= size)
    {
        fail_windows("invalid_path", "Could not canonicalize Windows path");
    }
    result.resize(length);
    std::replace(result.begin(), result.end(), L'/', L'\\');
    if (result.starts_with(L"\\\\?\\"))
    {
        if (result.starts_with(L"\\\\?\\UNC\\"))
        {
            result = L"\\\\" + result.substr(8);
        }
        else
        {
            result.erase(0, 4);
        }
    }
    return result;
}

bool same_path(const std::wstring &left, const std::wstring &right)
{
    const auto a = full_path(left);
    const auto b = full_path(right);
    return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

std::wstring dll_windows_path(const std::string &path)
{
    const auto decoded = from_utf8(path);
    if (path.front() == '/')
    {
        using wine_get_dos_file_name_fn = WCHAR *(__cdecl *)(const char *);
        using wine_get_unix_file_name_fn = char *(__cdecl *)(const WCHAR *);
        const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
        const auto map_path = std::bit_cast<wine_get_dos_file_name_fn>(
            GetProcAddress(kernel32, "wine_get_dos_file_name"));
        const auto unmap_path = std::bit_cast<wine_get_unix_file_name_fn>(
            GetProcAddress(kernel32, "wine_get_unix_file_name"));
        if (!map_path || !unmap_path)
        {
            throw failure("wine_path_mapping_unavailable",
                          "Linux paths require Wine's DOS and Unix filename conversion exports");
        }
        const std::unique_ptr<WCHAR, heap_deleter> mapped(map_path(path.c_str()));
        if (!mapped)
        {
            fail_windows("path_mapping_failed", "Wine could not map the Linux DLL path");
        }
        const auto normalized = full_path(mapped.get());
        const std::unique_ptr<char, heap_deleter> round_trip(unmap_path(normalized.c_str()));
        // Wine's host-code-page conversion can replace UTF-8 bytes in a C
        // locale. Verify the original filename before passing UTF-16 to the loader.
        if (!round_trip || path != round_trip.get())
        {
            throw failure("unsafe_path_mapping",
                          "Wine cannot round-trip this Linux filename in the active host locale. "
                          "Use an accessible ASCII path");
        }
        return normalized;
    }
    const bool drive_absolute =
        decoded.size() >= 3 && decoded[1] == L':' && (decoded[2] == L'\\' || decoded[2] == L'/');
    const bool unc_absolute = decoded.starts_with(L"\\\\");
    if (!drive_absolute && !unc_absolute)
    {
        throw failure("invalid_path", "DLL path must be an absolute Windows or Linux path");
    }
    return full_path(decoded);
}

std::wstring image_path(HANDLE process)
{
    std::wstring result(maximum_path_size, L'\0');
    DWORD size = static_cast<DWORD>(result.size());
    if (!QueryFullProcessImageNameW(process, 0, result.data(), &size))
    {
        fail_windows("process_query_failed", "Could not query target image path");
    }
    result.resize(size);
    return result;
}

std::uint64_t creation_time(HANDLE process)
{
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user))
    {
        fail_windows("process_query_failed", "Could not query process creation time");
    }
    return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

std::string architecture(HANDLE process)
{
    using is_wow64_process_2_fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
    const auto query = std::bit_cast<is_wow64_process_2_fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    if (query)
    {
        USHORT process_machine = 0;
        USHORT native_machine = 0;
        if (!query(process, &process_machine, &native_machine))
        {
            fail_windows("architecture_query_failed", "Could not query target architecture");
        }
        const USHORT machine =
            process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine;
        if (machine == IMAGE_FILE_MACHINE_AMD64)
        {
            return "x64";
        }
        if (machine == IMAGE_FILE_MACHINE_I386)
        {
            return "x86";
        }
        return "unknown";
    }
    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64))
    {
        fail_windows("architecture_query_failed", "Could not query target architecture");
    }
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    if (wow64 || info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
    {
        return "x86";
    }
    return info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "unknown";
}

void require_identity(HANDLE process, const std::wstring &expected_path,
                      std::uint64_t expected_creation)
{
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
    {
        throw failure("target_exited",
                      "Target has exited or its liveness could not be established");
    }
    if (creation_time(process) != expected_creation ||
        !same_path(image_path(process), expected_path))
    {
        throw failure("identity_mismatch",
                      "Target image path or creation FILETIME changed. Refresh the process list");
    }
}

void read_file_at(HANDLE file, std::uint64_t offset, void *buffer, DWORD size)
{
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
    {
        fail_windows("invalid_dll", "Could not seek DLL PE headers");
    }
    DWORD read = 0;
    if (!ReadFile(file, buffer, size, &read, nullptr) || read != size)
    {
        throw failure("invalid_dll", "DLL PE headers are truncated or unreadable");
    }
}

void validate_dll(HANDLE file)
{
    LARGE_INTEGER file_size{};
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileSizeEx(file, &file_size) ||
        file_size.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER)) ||
        file_size.QuadPart > std::numeric_limits<DWORD>::max())
    {
        throw failure("invalid_dll", "DLL must be a bounded, readable disk file");
    }
    const auto length = static_cast<std::uint64_t>(file_size.QuadPart);
    IMAGE_DOS_HEADER dos{};
    read_file_at(file, 0, &dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)))
        throw failure("invalid_dll", "DLL has no valid DOS/PE header");
    const auto nt_offset = static_cast<std::uint64_t>(dos.e_lfanew);
    constexpr auto fixed_size = offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
    if (nt_offset + fixed_size > length)
        throw failure("invalid_dll", "DLL PE header extends past end of file");
    IMAGE_NT_HEADERS64 nt{};
    read_file_at(file, nt_offset, &nt, static_cast<DWORD>(fixed_size));
    const auto optional_size = nt.FileHeader.SizeOfOptionalHeader;
    const auto directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        (nt.FileHeader.Characteristics & (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE)) !=
            (IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE) ||
        nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > 96 ||
        optional_size < directory_offset || optional_size > 4096 ||
        nt_offset + fixed_size + optional_size > length)
        throw failure("invalid_dll", "DLL has invalid PE headers");
    read_file_at(
        file, nt_offset + fixed_size, &nt.OptionalHeader,
        static_cast<DWORD>(std::min<std::size_t>(optional_size, sizeof(nt.OptionalHeader))));
    const auto &optional = nt.OptionalHeader;
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw failure("architecture_mismatch", "DLL must be an x64 PE32+ image");
    const auto section_offset = nt_offset + fixed_size + optional_size;
    const auto section_end =
        section_offset +
        static_cast<std::uint64_t>(nt.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    const auto alignment = optional.SectionAlignment;
    const auto file_alignment = optional.FileAlignment;
    const auto directories = optional.NumberOfRvaAndSizes;
    if (!std::has_single_bit(alignment) || !std::has_single_bit(file_alignment) ||
        alignment < file_alignment || file_alignment > 65536 ||
        (alignment < 4096 ? alignment != file_alignment : file_alignment < 512) ||
        !optional.SizeOfImage || optional.SizeOfImage % alignment != 0 ||
        optional.SizeOfHeaders < section_end || optional.SizeOfHeaders > length ||
        optional.SizeOfHeaders > optional.SizeOfImage ||
        optional.SizeOfHeaders % file_alignment != 0 ||
        optional.AddressOfEntryPoint >= optional.SizeOfImage || directories > 16 ||
        directory_offset + directories * sizeof(IMAGE_DATA_DIRECTORY) > optional_size)
        throw failure("invalid_dll", "DLL has invalid PE alignment or image/directory bounds");
    if (directories > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
        (optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress ||
         optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size))
        throw failure("invalid_dll", "Managed/.NET DLLs are unsupported");
    std::array<IMAGE_SECTION_HEADER, 96> sections{};
    bool executable_entry = optional.AddressOfEntryPoint == 0;
    const auto overlaps =
        [](std::uint64_t a, std::uint64_t size_a, std::uint64_t b, std::uint64_t size_b)
    { return size_a && size_b && a < b + size_b && b < a + size_a; };
    for (WORD index = 0; index < nt.FileHeader.NumberOfSections; ++index)
    {
        auto &section = sections[index];
        read_file_at(file, section_offset + index * sizeof(section), &section, sizeof(section));
        const auto address = static_cast<std::uint64_t>(section.VirtualAddress);
        const auto extent = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        const auto raw = static_cast<std::uint64_t>(section.PointerToRawData);
        const auto size = section.SizeOfRawData;
        if (address % alignment || address < optional.SizeOfHeaders ||
            address + extent > optional.SizeOfImage ||
            (size && (raw < optional.SizeOfHeaders || raw % file_alignment ||
                      size % file_alignment || raw + size > length)))
            throw failure("invalid_dll", "DLL section alignment or data bounds are invalid");
        for (WORD other = 0; other < index; ++other)
        {
            const auto &previous = sections[other];
            if (overlaps(address, extent, previous.VirtualAddress,
                         std::max(previous.Misc.VirtualSize, previous.SizeOfRawData)) ||
                overlaps(raw, size, previous.PointerToRawData, previous.SizeOfRawData))
                throw failure("invalid_dll", "DLL PE sections overlap");
        }
        if (optional.AddressOfEntryPoint >= address &&
            optional.AddressOfEntryPoint < address + size &&
            (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            executable_entry = true;
    }
    if (!executable_entry)
        throw failure("invalid_dll", "DLL entry point is not in backed executable data");
    for (DWORD index = 0; index < directories; ++index)
    {
        const auto address =
            static_cast<std::uint64_t>(optional.DataDirectory[index].VirtualAddress);
        const auto size = optional.DataDirectory[index].Size;
        if (!address && !size)
            continue;
        bool mapped = false;
        if (address && size)
        {
            if (index == IMAGE_DIRECTORY_ENTRY_SECURITY)
                mapped = address % 8 == 0 && address + size <= length;
            else
            {
                mapped = address + size <= optional.SizeOfHeaders;
                for (WORD section = 0; !mapped && section < nt.FileHeader.NumberOfSections;
                     ++section)
                    mapped = address >= sections[section].VirtualAddress &&
                             address + size <=
                                 static_cast<std::uint64_t>(sections[section].VirtualAddress) +
                                     sections[section].SizeOfRawData;
            }
        }
        if (!mapped)
            throw failure("invalid_dll", "DLL directory is outside backed image data");
    }
}

void require_same_file(HANDLE original, const std::wstring &path)
{
    // Hold both handles concurrently: volume + file index identify a file, not a
    // pathname. This detects replacement but cannot freeze native Unix path lookup.
    unique_handle current(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    if (!current || GetFileType(original) != FILE_TYPE_DISK ||
        GetFileType(current.get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(original, &before) ||
        !GetFileInformationByHandle(current.get(), &after) ||
        (before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (after.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        !(before.nFileIndexHigh || before.nFileIndexLow) ||
        before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
        before.nFileIndexHigh != after.nFileIndexHigh ||
        before.nFileIndexLow != after.nFileIndexLow ||
        before.nFileSizeHigh != after.nFileSizeHigh || before.nFileSizeLow != after.nFileSizeLow ||
        CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) != 0)
    {
        throw failure("dll_identity_changed",
                      "The DLL path no longer identifies the held, validated file");
    }
}

struct module_info
{
    std::wstring path;
    std::wstring name;
    std::uintptr_t base = 0;
    DWORD size = 0;
};

std::vector<module_info> modules(DWORD pid)
{
    HANDLE snapshot_value = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 8; ++attempt)
    {
        snapshot_value = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot_value != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH)
        {
            break;
        }
    }
    unique_handle snapshot(snapshot_value);
    if (!snapshot)
    {
        fail_windows("module_query_failed", "Could not snapshot target modules");
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry))
    {
        fail_windows("module_query_failed", "Could not enumerate target modules");
    }
    std::vector<module_info> result;
    do
    {
        // Toolhelp paths have a fixed MAX_PATH buffer. Never accept a potentially truncated
        // identity.
        const auto path_length = std::wcslen(entry.szExePath);
        if (path_length >= MAX_PATH - 1)
        {
            throw failure("module_path_too_long", "Target module path may be truncated by "
                                                  "Toolhelp. Identity cannot be verified safely");
        }
        result.push_back({entry.szExePath, entry.szModule,
                          reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize});
    } while (Module32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
    {
        fail_windows("module_query_failed", "Target module enumeration was interrupted");
    }
    return result;
}

void read_remote(HANDLE process, std::uintptr_t address, void *buffer, std::size_t size)
{
    SIZE_T received = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void *>(address), buffer, size,
                           &received) ||
        received != size)
    {
        fail_windows("loader_verification_failed", "Could not read the remote loader module");
    }
}

IMAGE_NT_HEADERS64 remote_headers(HANDLE process, const module_info &module)
{
    IMAGE_DOS_HEADER dos{};
    read_remote(process, module.base, &dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
        static_cast<std::uint64_t>(dos.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > module.size)
    {
        throw failure("loader_verification_failed", "Remote module has invalid DOS header bounds");
    }
    IMAGE_NT_HEADERS64 nt{};
    read_remote(process, module.base + dos.e_lfanew, &nt, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage != module.size)
    {
        throw failure("loader_verification_failed", "Remote module is not a matching x64 PE image");
    }
    return nt;
}

LPTHREAD_START_ROUTINE remote_export(HANDLE process, const std::vector<module_info> &target_modules,
                                     const char *export_name)
{
    const auto loader = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), export_name);
    if (!loader)
    {
        throw failure("loader_resolution_failed",
                      std::string("Local export could not be resolved: ") + export_name,
                      GetLastError());
    }
    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQuery(reinterpret_cast<const void *>(loader), &memory, sizeof(memory)) ||
        memory.Type != MEM_IMAGE)
    {
        throw failure("loader_resolution_failed",
                      std::string("Resolved export does not belong to a PE image: ") + export_name);
    }
    const auto owner = reinterpret_cast<HMODULE>(memory.AllocationBase);
    std::wstring owner_path(maximum_path_size, L'\0');
    const DWORD path_length =
        GetModuleFileNameW(owner, owner_path.data(), static_cast<DWORD>(owner_path.size()));
    if (!path_length || path_length >= owner_path.size())
    {
        fail_windows("loader_resolution_failed",
                     "Could not identify the module owning the resolved export");
    }
    owner_path.resize(path_length);
    const auto owner_base = reinterpret_cast<std::uintptr_t>(owner);
    const auto loader_address = reinterpret_cast<std::uintptr_t>(loader);
    const auto local_dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(owner);
    if (local_dos->e_magic != IMAGE_DOS_SIGNATURE ||
        local_dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        local_dos->e_lfanew > 1024 * 1024)
    {
        throw failure("loader_resolution_failed", "Local loader module has invalid PE headers");
    }
    const auto local_nt =
        reinterpret_cast<const IMAGE_NT_HEADERS64 *>(owner_base + local_dos->e_lfanew);
    if (local_nt->Signature != IMAGE_NT_SIGNATURE ||
        local_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        local_nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        throw failure("loader_resolution_failed", "Local loader module is not an x64 PE image");
    }
    const auto rva = loader_address - owner_base;
    constexpr std::size_t compared_bytes = 32;
    if (loader_address < owner_base ||
        rva + compared_bytes > local_nt->OptionalHeader.SizeOfImage ||
        loader_address + compared_bytes >
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress) + memory.RegionSize)
    {
        throw failure("loader_resolution_failed",
                      "Resolved export address is outside its owning image");
    }
    for (const auto &module : target_modules)
    {
        if (!same_path(module.path, owner_path))
        {
            continue;
        }
        const auto remote_nt = remote_headers(process, module);
        if (remote_nt.FileHeader.TimeDateStamp != local_nt->FileHeader.TimeDateStamp ||
            remote_nt.FileHeader.SizeOfOptionalHeader !=
                local_nt->FileHeader.SizeOfOptionalHeader ||
            remote_nt.OptionalHeader.SizeOfImage != local_nt->OptionalHeader.SizeOfImage ||
            remote_nt.OptionalHeader.CheckSum != local_nt->OptionalHeader.CheckSum ||
            rva + compared_bytes > module.size)
        {
            throw failure("loader_verification_failed",
                          "Remote loader module identity differs from the local owning image");
        }
        std::array<unsigned char, compared_bytes> bytes{};
        read_remote(process, module.base + rva, bytes.data(), bytes.size());
        if (std::memcmp(bytes.data(), reinterpret_cast<const void *>(loader_address),
                        bytes.size()) != 0)
        {
            throw failure("loader_verification_failed",
                          "Remote function bytes differ. Refusing an unverified entry point");
        }
        MEMORY_BASIC_INFORMATION remote_memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<const void *>(module.base + rva),
                            &remote_memory, sizeof(remote_memory)) ||
            remote_memory.Type != MEM_IMAGE ||
            reinterpret_cast<std::uintptr_t>(remote_memory.AllocationBase) != module.base ||
            (remote_memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                      PAGE_EXECUTE_WRITECOPY)) == 0 ||
            (remote_memory.Protect & PAGE_GUARD) != 0)
        {
            throw failure("loader_verification_failed",
                          "Remote export is not executable image memory");
        }
        return reinterpret_cast<LPTHREAD_START_ROUTINE>(module.base + rva);
    }
    throw failure("loader_verification_failed",
                  "Target does not contain the same module that owns the local export");
}

DWORD remaining_timeout(ULONGLONG deadline)
{
    const ULONGLONG now = GetTickCount64();
    return now < deadline ? static_cast<DWORD>(deadline - now) : 0;
}

std::string required_string(const json &request, const char *name, std::size_t maximum)
{
    if (!request.contains(name) || !request[name].is_string())
    {
        throw failure("invalid_request", std::string("Missing or non-string field: ") + name);
    }
    const auto value = request[name].get<std::string>();
    if (value.empty() || value.size() > maximum || value.find('\0') != std::string::npos)
    {
        throw failure("invalid_request",
                      std::string("Empty, oversized or NUL-containing field: ") + name);
    }
    return value;
}

std::uint64_t required_integer(const json &request, const char *name, std::uint64_t minimum,
                               std::uint64_t maximum)
{
    if (!request.contains(name) || !request[name].is_number_integer())
    {
        throw failure("invalid_request", std::string("Missing or non-integer field: ") + name);
    }
    if (request[name].is_number_integer() && !request[name].is_number_unsigned() &&
        request[name].get<std::int64_t>() < 0)
    {
        throw failure("invalid_request", std::string("Negative field: ") + name);
    }
    const auto value = request[name].get<std::uint64_t>();
    if (value < minimum || value > maximum)
    {
        throw failure("invalid_request", std::string("Out-of-range field: ") + name);
    }
    return value;
}

void validate_fields(const json &request, const std::set<std::string> &allowed)
{
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
    // Fixture-only envelope fields never enter the production protocol.
    static const std::set<std::string> fixture_fields = {"fixture_session", "fixture_targets"};
#endif
    for (const auto &item : request.items())
    {
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
        if (fixture_fields.contains(item.key()))
            continue;
#endif
        if (!allowed.contains(item.key()))
        {
            throw failure("invalid_request", "Unknown request field: " + item.key());
        }
    }
}

#ifdef PROTON_NEEDLE_FIXTURE_TESTING
json fixture_targets;
std::wstring fixture_session;
void require_fixture_evidence(const json &target);

void authorize_fixture_session(const json &request)
{
    const auto session = required_string(request, "fixture_session", 32);
    if (session.size() != 32 || session.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw failure("fixture_safety", "Invalid fixture session token");
    wchar_t inherited[33]{};
    if (GetEnvironmentVariableW(L"PROTON_NEEDLE_FIXTURE_SESSION", inherited, 33) != 32 ||
        from_utf8(session) != inherited)
        throw failure("fixture_safety",
                      "Fixture session token does not match isolated environment");
    if (!request.contains("fixture_targets") || !request["fixture_targets"].is_array() ||
        request["fixture_targets"].empty() || request["fixture_targets"].size() > 64)
        throw failure("fixture_safety", "Missing or oversized fixture target registry");
    fixture_session = from_utf8(session);
    fixture_targets = request["fixture_targets"];
    std::set<DWORD> pids;
    for (const auto &target : fixture_targets)
    {
        if (!target.is_object() || target.size() != 4 || !target.contains("windows_pid") ||
            !target.contains("image_path") || !target.contains("creation_time") ||
            !target.contains("fixture_instance"))
            throw failure("fixture_safety", "Malformed fixture target envelope");
        const DWORD pid = static_cast<DWORD>(
            required_integer(target, "windows_pid", 1, std::numeric_limits<DWORD>::max()));
        const auto path = from_utf8(required_string(target, "image_path", maximum_path_size));
        const auto creation = required_string(target, "creation_time", 20);
        const auto instance = required_string(target, "fixture_instance", 32);
        if (instance.size() != 32 ||
            instance.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw failure("fixture_safety", "Malformed fixture launch instance");
        std::uint64_t ticks = 0;
        const auto parsed =
            std::from_chars(creation.data(), creation.data() + creation.size(), ticks);
        if (parsed.ec != std::errc{} || parsed.ptr != creation.data() + creation.size() || !ticks ||
            std::to_string(ticks) != creation || !pids.insert(pid).second)
            throw failure("fixture_safety", "Malformed fixture creation identity");
        const auto name = path.substr(path.find_last_of(L"\\/") + 1);
        if (name != L"proton_needle_test_target.exe")
            throw failure("fixture_safety", "Nonfixture image refused");
        require_fixture_evidence(target);
    }
}

const json *fixture_target(DWORD pid)
{
    for (const auto &target : fixture_targets)
        if (target["windows_pid"].get<DWORD>() == pid)
            return &target;
    return nullptr;
}

void require_fixture_evidence(const json &target)
{
    const auto event = L"Local\\ProtonNeedleFixture_" + fixture_session + L"_" +
                       from_utf8(target["fixture_instance"].get<std::string>()) + L"_" +
                       std::to_wstring(target["windows_pid"].get<DWORD>()) + L"_" +
                       from_utf8(target["creation_time"].get<std::string>());
    unique_handle proof(OpenEventW(SYNCHRONIZE, FALSE, event.c_str()));
    if (!proof || WaitForSingleObject(proof.get(), 0) != WAIT_OBJECT_0)
        throw failure("fixture_safety", "No live fixture session/readiness evidence");
}
#endif

json wine_metadata()
{
    using wine_get_version_fn = const char *(__cdecl *)();
    const auto version_function = std::bit_cast<wine_get_version_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version"));
    const char *version = version_function ? version_function() : nullptr;
    return {{"wine_version", version ? version : ""}, {"wine_detected", version != nullptr}};
}

json probe()
{
    auto result = wine_metadata();
    result.update({{"architecture", "x64"},
                   {"helper_windows_pid", GetCurrentProcessId()},
                   {"methods", json::array({"load_library_w"})}});
    return result;
}

json list_processes()
{
    unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot)
    {
        fail_windows("process_list_failed", "Could not snapshot Windows processes");
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry))
    {
        fail_windows("process_list_failed", "Could not enumerate Windows processes");
    }
    json processes = json::array();
    std::size_t skipped = 0;
    do
    {
        if (!entry.th32ProcessID || entry.th32ProcessID == GetCurrentProcessId())
        {
            continue;
        }
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
        const auto *registered = fixture_target(entry.th32ProcessID);
        if (!registered)
            continue;
        try
        {
            require_fixture_evidence(*registered);
        }
        catch (const failure &)
        {
            ++skipped;
            continue;
        }
#endif
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
        constexpr DWORD query_access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
#else
        constexpr DWORD query_access = PROCESS_QUERY_LIMITED_INFORMATION;
#endif
        unique_handle process(OpenProcess(query_access, FALSE, entry.th32ProcessID));
        if (!process)
        {
            ++skipped;
            continue;
        }
        try
        {
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
            require_identity(process.get(),
                             from_utf8((*registered)["image_path"].get<std::string>()),
                             std::stoull((*registered)["creation_time"].get<std::string>()));
#endif
            processes.push_back({{"windows_pid", entry.th32ProcessID},
                                 {"name", to_utf8(entry.szExeFile)},
                                 {"image_path", to_utf8(image_path(process.get()))},
                                 {"creation_time", std::to_string(creation_time(process.get()))},
                                 {"architecture", architecture(process.get())}});
        }
        catch (const failure &)
        {
            ++skipped;
        }
    } while (Process32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
    {
        fail_windows("process_list_failed", "Windows process enumeration was interrupted");
    }
    auto result = wine_metadata();
    result.update({{"processes", std::move(processes)}, {"skipped_processes", skipped}});
    return result;
}

json inject(const json &request, bool &loading_started)
{
    validate_fields(request, {"protocol_version", "request_id", "operation", "target_windows_pid",
                              "expected_image_path", "expected_creation_time", "dll_path", "method",
                              "timeout_ms"});
    const DWORD pid = static_cast<DWORD>(
        required_integer(request, "target_windows_pid", 1, std::numeric_limits<DWORD>::max()));
    if (pid == GetCurrentProcessId())
    {
        throw failure("invalid_target", "The helper cannot inject into itself");
    }
    const auto expected_path =
        from_utf8(required_string(request, "expected_image_path", maximum_path_size));
    const auto time_text = required_string(request, "expected_creation_time", 20);
    std::uint64_t expected_creation = 0;
    const auto parsed_time =
        std::from_chars(time_text.data(), time_text.data() + time_text.size(), expected_creation);
    if (parsed_time.ec != std::errc{} || parsed_time.ptr != time_text.data() + time_text.size() ||
        !expected_creation)
    {
        throw failure("invalid_request",
                      "expected_creation_time must be a nonzero unsigned decimal FILETIME string");
    }
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
    const auto *registered = fixture_target(pid);
    if (!registered)
        throw failure("fixture_safety", "Unregistered Windows target refused");
    if (registered->at("image_path").get<std::string>() != to_utf8(expected_path) ||
        registered->at("creation_time").get<std::string>() != time_text)
        throw failure("identity_mismatch", "Fixture Windows identity does not match registry");
    // Check token-bound fixture evidence BEFORE opening or touching the target.
    require_fixture_evidence(*registered);
#endif
    if (required_string(request, "method", 64) != "load_library_w")
    {
        throw failure("unsupported_method", "Only load_library_w is implemented");
    }
    const DWORD timeout = static_cast<DWORD>(required_integer(request, "timeout_ms", 1, 120000));
    const auto dll_path = dll_windows_path(required_string(request, "dll_path", maximum_path_size));
    unique_handle dll_file(CreateFileW(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!dll_file)
    {
        fail_windows("dll_open_failed",
                     "DLL cannot be opened read-only. File must remain unchanged during injection");
    }
    validate_dll(dll_file.get());
    require_same_file(dll_file.get(), dll_path);
    unique_handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
                                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                          PROCESS_VM_READ | SYNCHRONIZE,
                                      FALSE, pid));
    if (!process)
    {
        fail_windows("target_open_failed", "Could not open target with required injection rights");
    }
    require_identity(process.get(), expected_path, expected_creation);
    if (architecture(process.get()) != "x64")
    {
        throw failure("architecture_mismatch", "Only x64 targets can be injected by this helper");
    }
    const auto target_modules = modules(pid);
    for (const auto &module : target_modules)
    {
        if (same_path(module.path, dll_path))
        {
            throw failure("dll_already_loaded",
                          "The exact DLL path is already loaded in the target");
        }
    }
    const ULONGLONG deadline = GetTickCount64() + timeout;
    const auto loader = remote_export(process.get(), target_modules, "LoadLibraryW");
    const auto path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    remote_buffer buffer(process.get(), path_bytes);
    SIZE_T written = 0;
    if (!WriteProcessMemory(process.get(), buffer.get(), dll_path.c_str(), path_bytes, &written) ||
        written != path_bytes)
    {
        fail_windows("remote_write_failed", "Could not write the complete remote DLL path");
    }
    require_identity(process.get(), expected_path, expected_creation);
    require_same_file(dll_file.get(), dll_path);
    if (remaining_timeout(deadline) == 0)
    {
        throw failure("preflight_timeout", "Operation deadline expired before DLL loading started");
    }
    unique_handle thread(
        CreateRemoteThread(process.get(), nullptr, 0, loader, buffer.get(), 0, nullptr));
    if (!thread)
    {
        fail_windows("remote_thread_failed",
                     "Could not start the verified remote LoadLibraryW entry point");
    }
    loading_started = true;
    const DWORD wait_result = WaitForSingleObject(thread.get(), remaining_timeout(deadline));
    if (wait_result != WAIT_OBJECT_0)
    {
        // The thread may still read its argument. Freeing it here would be a remote use-after-free.
        buffer.retain();
        if (wait_result == WAIT_TIMEOUT)
        {
            throw failure("injection_timeout",
                          "Remote loader timed out. Its path allocation is intentionally retained "
                          "and the thread is not terminated",
                          0, true);
        }
        fail_windows(
            "remote_wait_failed",
            "Remote thread state is unknown. Its path allocation is intentionally retained", true);
    }
    DWORD exit_code = 0;
    if (!GetExitCodeThread(thread.get(), &exit_code))
    {
        fail_windows("remote_thread_query_failed", "Could not query completed remote thread", true);
    }
    // A DWORD thread exit code truncates HMODULE on x64. Only a verified full module path proves
    // loading.
    require_identity(process.get(), expected_path, expected_creation);
    for (const auto &module : modules(pid))
    {
        if (same_path(module.path, dll_path))
        {
            remote_headers(process.get(), module);
            require_same_file(dll_file.get(), module.path);
            return {{"verified", true},
                    {"target_windows_pid", pid},
                    {"target_image_path", to_utf8(expected_path)},
                    {"target_creation_time", std::to_string(expected_creation)},
                    {"file_identity_verified", true},
                    {"loaded_module_path", to_utf8(module.path)},
                    {"module_base", std::to_string(module.base)},
                    {"remote_thread_exit_code", exit_code},
                    {"method", "load_library_w"}};
        }
    }
    throw failure("load_library_failed",
                  "Remote loader completed but the exact DLL path was not present in the target "
                  "module list. DLL code may already have executed",
                  0, true);
}
} // namespace

int wmain(int argc, wchar_t **argv)
{
    json response = {{"protocol_version", 1}, {"request_id", ""}, {"operation", ""},
                     {"status", "error"},     {"error_code", ""}, {"error_message", ""}};
    bool loading_started = false;
    try
    {
        std::string line;
        if (argc == 3 && std::wstring_view(argv[1]) == L"--request-json")
        {
            line = to_utf8(argv[2]);
        }
        else if (argc == 1)
        {
            line.reserve(4096);
            char character = 0;
            while (std::cin.get(character) && character != '\n')
            {
                if (line.size() >= maximum_request_size)
                {
                    throw failure("request_too_large", "JSON request exceeds 65536 bytes");
                }
                line.push_back(character);
            }
        }
        else
        {
            throw failure("invalid_request", "Use stdin or --request-json with one JSON object");
        }
        if (line.size() > maximum_request_size)
        {
            throw failure("request_too_large", "JSON request exceeds 65536 bytes");
        }
        if (line.empty())
        {
            throw failure("invalid_request", "Expected one JSON request on stdin");
        }
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
        std::vector<std::set<std::string>> keys;
#else
        std::set<std::string> keys;
#endif
        bool duplicate_key = false;
        const auto request =
            json::parse(line,
                        [&keys, &duplicate_key](int, json::parse_event_t event, json &parsed)
                        {
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
                            if (event == json::parse_event_t::object_start)
                                keys.emplace_back();
                            else if (event == json::parse_event_t::object_end)
                                keys.pop_back();
                            else if (event == json::parse_event_t::key &&
                                     !keys.back().insert(parsed.get<std::string>()).second)
                            {
                                duplicate_key = true;
                            }
#else
                            if (event == json::parse_event_t::key &&
                                !keys.insert(parsed.get<std::string>()).second)
                            {
                                duplicate_key = true;
                            }
#endif
                            return true;
                        });
        if (!request.is_object() || duplicate_key)
        {
            throw failure("invalid_request", "Request must be an object without duplicate keys");
        }
        response["request_id"] = required_string(request, "request_id", 128);
        response["operation"] = required_string(request, "operation", 32);
        required_integer(request, "protocol_version", 1, 1);
#ifdef PROTON_NEEDLE_FIXTURE_TESTING
        authorize_fixture_session(request);
#endif
        const auto operation = response["operation"].get<std::string>();
        json result;
        if (operation == "probe")
        {
            validate_fields(request, {"protocol_version", "request_id", "operation"});
            result = probe();
        }
        else if (operation == "list_processes")
        {
            validate_fields(request, {"protocol_version", "request_id", "operation"});
            result = list_processes();
        }
        else if (operation == "inject")
        {
            result = inject(request, loading_started);
        }
        else
        {
            throw failure("unsupported_operation",
                          "Operation must be probe, list_processes or inject");
        }
        response.update(result);
        response["status"] = "success";
    }
    catch (const failure &error)
    {
        response["status"] = "error";
        response["error_code"] = error.code;
        response["error_message"] = error.what();
        response["inconclusive"] = loading_started || error.inconclusive;
        if (error.system_error)
        {
            response["win32_error"] = error.system_error;
        }
    }
    catch (const json::exception &error)
    {
        response["status"] = "error";
        response["error_code"] = loading_started ? "helper_failure" : "invalid_request";
        response["error_message"] = error.what();
        response["inconclusive"] = loading_started;
    }
    catch (const std::exception &error)
    {
        response["status"] = "error";
        response["error_code"] = "helper_failure";
        response["error_message"] = error.what();
        response["inconclusive"] = loading_started;
    }
    std::cout << response.dump(-1, ' ', false, json::error_handler_t::replace) << '\n';
    std::cout.flush();
    return response["status"] == "success" ? 0 : 1;
}
