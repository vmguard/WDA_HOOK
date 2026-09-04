#include "utils.hpp"
#include "kernel_modules.hpp"
#include "pe.hpp"

#pragma comment( lib, "ntoskrnl.lib" )
//
// WDK doesn't expose these fully — define manually.
//
typedef struct _PEB_LDR_DATA
{
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE  Mutant;
    PVOID   ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // rest of PEB not needed
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//
// Undocumented kernel functions — declare manually.
//
extern "C"
{
    PVOID  NTAPI PsGetProcessWin32Process(PEPROCESS Process);
    PPEB   NTAPI PsGetProcessPeb(PEPROCESS Process);
}

bool data_compare(const char* pdata, const char* bmask, const char* szmask)
{
    for (; *szmask; ++szmask, ++pdata, ++bmask)
    {
        if (*szmask == 'x' && *pdata != *bmask)
            return false;
    }
    return !*szmask;
}

uintptr_t utils::find_pattern(const uintptr_t base, const size_t size, const char* bmask, const char* szmask)
{
    for (size_t i = 0; i < size; ++i)
        if (data_compare(reinterpret_cast<const char*>(base + i), bmask, szmask))
            return base + i;
    return 0;
}

uintptr_t utils::find_pattern_section(const uintptr_t base, const char* szsection, const char* bmask, const char* szmask)
{
    if (!base || !szsection || !bmask || !szmask)
        return 0;
    const auto* psection = pe::get_section_header(base, szsection);
    return psection ? find_pattern(base + psection->VirtualAddress, psection->SizeOfRawData, bmask, szmask) : 0;
}

uintptr_t utils::find_pattern_km(const wchar_t* szmodule, const char* szsection, const char* bmask, const char* szmask)
{
    if (!szmodule || !szsection || !bmask || !szmask)
        return 0;
    const auto module_base = kernel_modules::get_kernel_module_base(szmodule);
    return module_base ? find_pattern_section(module_base, szsection, bmask, szmask) : 0;
}

void* utils::get_system_routine(const wchar_t* szroutine)
{
    if (!szroutine)
        return nullptr;
    UNICODE_STRING routine{ };
    RtlInitUnicodeString(&routine, szroutine);
    return MmGetSystemRoutineAddress(&routine);
}

uintptr_t utils::get_ntos_base()
{
    using f_RtlPcToFileHeader = PVOID(*)(PVOID PcValue, PVOID* BaseOfImage);
    const auto RtlPcToFileHeader = reinterpret_cast<f_RtlPcToFileHeader>(get_system_routine(L"RtlPcToFileHeader"));
    if (!RtlPcToFileHeader)
        return 0;
    uintptr_t ntos_base = 0;
    RtlPcToFileHeader(RtlPcToFileHeader, reinterpret_cast<void**>(&ntos_base));
    return ntos_base;
}

bool utils::init()
{
    const auto ntos_base = get_ntos_base();
    if (!ntos_base)
        return false;

    PsLoadedModuleList = reinterpret_cast<PLIST_ENTRY>(get_system_routine(L"PsLoadedModuleList"));
    if (!PsLoadedModuleList)
    {
        auto result = find_pattern_section
        (
            ntos_base, ".text",
            "\xC7\x43\x00\x00\x00\x00\x00\x48\x89\x43\x18\x48\x8D",
            "xx?????xxxxxx"
        );
        if (!result)
            return false;
        result += 0xB;
        PsLoadedModuleList = reinterpret_cast<PLIST_ENTRY>(result + *reinterpret_cast<int*>(result + 0x3) + 0x7);
    }

    PsLoadedModuleResource = reinterpret_cast<PERESOURCE>(get_system_routine(L"PsLoadedModuleResource"));
    if (!PsLoadedModuleResource)
    {
        auto result = find_pattern_section(ntos_base, ".text", "\x41\x23\xFF\x66", "xxxx");
        if (!result)
            return false;
        result += 0xA;
        PsLoadedModuleResource = reinterpret_cast<PERESOURCE>(result + *reinterpret_cast<int*>(result + 0x3) + 0x7);
    }

    return PsLoadedModuleList && PsLoadedModuleResource;
}

//
// Walks a user-mode process's PEB LDR module list looking for win32u.dll,
// then parses its export table and reads the syscall index from the stub.
// Must be called with the process attached via KeStackAttachProcess.
//
static uintptr_t find_win32u_base(PPEB peb)
{
    if (!peb)
        return 0;

    const auto ldr = peb->Ldr;
    if (!ldr)
        return 0;

    //
    // Walk InLoadOrderModuleList.
    //
    for (auto entry = ldr->InLoadOrderModuleList.Flink;
        entry != &ldr->InLoadOrderModuleList;
        entry = entry->Flink)
    {
        const auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (mod->BaseDllName.Buffer &&
            _wcsicmp(mod->BaseDllName.Buffer, L"win32u.dll") == 0)
        {
            return reinterpret_cast<uintptr_t>(mod->DllBase);
        }
    }

    return 0;
}

unsigned short utils::get_shadow_ssdt_index(const char* function_name)
{
    if (!function_name)
        return 0;

    unsigned short index = 0;
    PEPROCESS      process = nullptr;

    //
    // Find a suitable GUI process that will have win32u.dll loaded.
    // We look for explorer.exe or any process with a non-null Win32Process.
    // Iterate PIDs starting from 4, stepping by 4.
    //
    for (ULONG pid = 4; pid < 0x10000; pid += 4)
    {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process)))
            continue;

        //
        // Skip processes with no Win32 thread / GUI context.
        // PsGetProcessWin32Process returns non-null for GUI processes.
        //
        if (!PsGetProcessWin32Process(process))
        {
            ObDereferenceObject(process);
            process = nullptr;
            continue;
        }

        //
        // Found a GUI process — attach and try to resolve.
        //
        KAPC_STATE apc{ };
        KeStackAttachProcess(process, &apc);

        __try
        {
            const auto peb = PsGetProcessPeb(process);
            const auto base = find_win32u_base(peb);

            if (base)
            {
                const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
                const auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
                const auto exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

                if (exp_rva)
                {
                    const auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + exp_rva);
                    const auto names = reinterpret_cast<ULONG*>(base + exports->AddressOfNames);
                    const auto funcs = reinterpret_cast<ULONG*>(base + exports->AddressOfFunctions);
                    const auto ords = reinterpret_cast<USHORT*>(base + exports->AddressOfNameOrdinals);

                    for (ULONG i = 0; i < exports->NumberOfNames; i++)
                    {
                        const auto name = reinterpret_cast<const char*>(base + names[i]);

                        if (strcmp(name, function_name) != 0)
                            continue;

                        const auto func = reinterpret_cast<UCHAR*>(base + funcs[ords[i]]);

                        //
                        // Syscall stub pattern: B8 ?? ?? 00 00 (mov eax, index)
                        //
                        if (func[0] == 0xB8 && func[3] == 0x00 && func[4] == 0x00)
                            index = *reinterpret_cast<unsigned short*>(func + 1);

                        break;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(process);
        process = nullptr;

        if (index)
            break;
    }

    return index;
}