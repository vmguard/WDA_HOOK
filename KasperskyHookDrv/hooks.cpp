#include "hooks.hpp"
#include "utils.hpp"
/*
* I am sorry if I didn't stick to comment norms for this please forgive me ipower
*/

#define PROCESS_TO_HIDE L"notepad.exe"


#define WDA_NONE               0x00000000
#define WDA_MONITOR            0x00000001
#define WDA_EXCLUDEFROMCAPTURE 0x00000011


typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


NTSTATUS hooks::hk_NtCreateFile
(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
)
{
    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer)
    {
        const auto name = ObjectAttributes->ObjectName->Buffer;
        if (wcsstr(name, L"you_wont_open_this.txt"))
            return STATUS_ACCESS_DENIED;
    }

    return o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength);
}


static void filter_process_list(PVOID SystemInformation)
{
    auto current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
    PSYSTEM_PROCESS_INFORMATION previous = nullptr;

    while (true)
    {
        if (current->ImageName.Buffer &&
            wcsstr(current->ImageName.Buffer, PROCESS_TO_HIDE))
        {
            if (previous)
            {
                if (current->NextEntryOffset == 0)
                    previous->NextEntryOffset = 0;
                else
                    previous->NextEntryOffset += current->NextEntryOffset;
            }
            else if (current->NextEntryOffset != 0)
            {
                // Target is the first entry, shuffle memory forward so the callers buffer pointer still points to a valid entry
                auto next = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<ULONG_PTR>(current) + current->NextEntryOffset
                    );
                RtlMoveMemory(current, next, sizeof(SYSTEM_PROCESS_INFORMATION));
                continue; // recheck the current slot, which now holds the next entry
            }
        }
        else
        {
            previous = current;
        }

        if (current->NextEntryOffset == 0)
            break;

        current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<ULONG_PTR>(current) + current->NextEntryOffset
            );
    }
}


NTSTATUS hooks::hk_NtQuerySystemInformation
(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
)
{
    NTSTATUS status = o_NtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (!NT_SUCCESS(status))
        return status;

    if (SystemInformationClass == SystemProcessInformation ||
        SystemInformationClass == SystemExtendedProcessInformation)
    {
        filter_process_list(SystemInformation);
    }

    return status;
}


NTSTATUS hooks::hk_NtUserSetWindowDisplayAffinity
(
    HWND  hWnd,
    DWORD dwAffinity
)
{
    if (dwAffinity == WDA_EXCLUDEFROMCAPTURE)
    {
        DbgPrint("Blocking WDA_EXCLUDEFROMCAPTURE on HWND %p\n", hWnd);
        dwAffinity = WDA_NONE;
    }

    return o_NtUserSetWindowDisplayAffinity(hWnd, dwAffinity);
}


NTSTATUS hooks::hk_NtUserGetWindowDisplayAffinity
(
    HWND   hWnd,
    DWORD* pdwAffinity
)
{
    NTSTATUS status = o_NtUserGetWindowDisplayAffinity(hWnd, pdwAffinity);

    if (NT_SUCCESS(status) && pdwAffinity)
    {
        DbgPrint("GetWindowDisplayAffinity HWND %p real: %lu,  reporting WDA_NONE\n", hWnd, *pdwAffinity);
        *pdwAffinity = WDA_NONE;
    }

    return status;
}