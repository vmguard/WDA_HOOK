#pragma once
#include <ntifs.h>
#include <windef.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemSessionProcessInformation = 53,
    SystemExtendedProcessInformation = 57,
} SYSTEM_INFORMATION_CLASS;

using f_NtCreateFile = NTSTATUS(*)
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
    );

using f_NtQuerySystemInformation = NTSTATUS(*)
(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

using f_NtUserSetWindowDisplayAffinity = NTSTATUS(*)
(
    HWND  hWnd,
    DWORD dwAffinity
    );

using f_NtUserGetWindowDisplayAffinity = NTSTATUS(*)
(
    HWND   hWnd,
    DWORD* pdwAffinity
    );

namespace hooks
{
    NTSTATUS hk_NtCreateFile
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
    );

    NTSTATUS hk_NtQuerySystemInformation
    (
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength
    );

    NTSTATUS hk_NtUserSetWindowDisplayAffinity
    (
        HWND  hWnd,
        DWORD dwAffinity
    );

    NTSTATUS hk_NtUserGetWindowDisplayAffinity
    (
        HWND   hWnd,
        DWORD* pdwAffinity
    );
}

inline f_NtCreateFile                    o_NtCreateFile = nullptr;
inline f_NtQuerySystemInformation        o_NtQuerySystemInformation = nullptr;
inline f_NtUserSetWindowDisplayAffinity  o_NtUserSetWindowDisplayAffinity = nullptr;
inline f_NtUserGetWindowDisplayAffinity  o_NtUserGetWindowDisplayAffinity = nullptr;