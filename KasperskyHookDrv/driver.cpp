#include "kaspersky.hpp"
#include "hooks.hpp"
#include "utils.hpp"

DRIVER_UNLOAD DriverUnload;


constexpr unsigned short NtCreateFile_index = 0x0055;
constexpr unsigned short NtQuerySystemInformation_index = 0x0036;


unsigned short NtUserSetWindowDisplayAffinity_index = 0;
unsigned short NtUserGetWindowDisplayAffinity_index = 0;

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = &DriverUnload;

    //
    // Initialize kernel utility pointers.
    //
    if (!utils::init())
    {
        log("Failed to initialize kernel pointers!");
        return STATUS_ORDINAL_NOT_FOUND;
    }

    //
    // Make sure klhk.sys is loaded and initialize pattern-scanned pointers.
    //
    if (!kaspersky::is_klhk_loaded() || !kaspersky::initialize())
    {
        log("Failed to initialize klhk.sys data!");
        return STATUS_NOT_FOUND;
    }

    //
    // Bring up the hypervisor.
    //
    const auto hvm_status = kaspersky::hvm_init();

    if (!NT_SUCCESS(hvm_status))
    {
        log("hvm_init failed! Status: 0x%X", hvm_status);
        return hvm_status;
    }

    log("Hypervisor initialized. SSDT: %u, Shadow SSDT: %u",
        kaspersky::get_svc_count_ssdt(),
        kaspersky::get_svc_count_shadow_ssdt());

    //
    // Wait for klhk to finish building the Shadow SSDT table.
    // Poll up to 5 seconds in 100ms increments.
    //
    for (int i = 0; i < 50; i++)
    {
        if (kaspersky::get_svc_count_shadow_ssdt() > 0)
            break;

        LARGE_INTEGER delay{ };
        delay.QuadPart = -1000000; // 100ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    log("Shadow SSDT count after wait: %u", kaspersky::get_svc_count_shadow_ssdt());


    // Attempt dynamic Shadow SSDT index resolution, was honestly 50/50- for me

    NtUserSetWindowDisplayAffinity_index = utils::get_shadow_ssdt_index("NtUserSetWindowDisplayAffinity");
    NtUserGetWindowDisplayAffinity_index = utils::get_shadow_ssdt_index("NtUserGetWindowDisplayAffinity");

    log("Dynamic resolution — Set: 0x%X, Get: 0x%X",
        NtUserSetWindowDisplayAffinity_index,
        NtUserGetWindowDisplayAffinity_index);

   // 10, 22h2
    if (!NtUserSetWindowDisplayAffinity_index)
    {
        log("Dynamic resolution failed for Set, using hardcoded fallback 0x14F6.");
        NtUserSetWindowDisplayAffinity_index = 0x14F6;
    }

    if (!NtUserGetWindowDisplayAffinity_index)
    {
        log("Dynamic resolution failed for Get, using hardcoded fallback 0x1447.");
        NtUserGetWindowDisplayAffinity_index = 0x1447;
    }

    log("Final indexes — Set: 0x%X, Get: 0x%X",
        NtUserSetWindowDisplayAffinity_index,
        NtUserGetWindowDisplayAffinity_index);



    if (!kaspersky::hook_ssdt_routine(NtCreateFile_index,
        &hooks::hk_NtCreateFile,
        reinterpret_cast<void**>(&o_NtCreateFile)))
    {
        log("Failed to hook NtCreateFile!");
        return STATUS_UNSUCCESSFUL;
    }

    log("NtCreateFile hooked.");

    if (!kaspersky::hook_ssdt_routine(NtQuerySystemInformation_index,
        &hooks::hk_NtQuerySystemInformation,
        reinterpret_cast<void**>(&o_NtQuerySystemInformation)))
    {
        log("Failed to hook NtQuerySystemInformation!");
        kaspersky::unhook_ssdt_routine(NtCreateFile_index, o_NtCreateFile);
        return STATUS_UNSUCCESSFUL;
    }

    log("NtQuerySystemInformation hooked.");


    if (!kaspersky::hook_shadow_ssdt_routine(NtUserSetWindowDisplayAffinity_index,
        &hooks::hk_NtUserSetWindowDisplayAffinity,
        reinterpret_cast<void**>(&o_NtUserSetWindowDisplayAffinity)))
    {
        log("Failed to hook NtUserSetWindowDisplayAffinity!");
        kaspersky::unhook_ssdt_routine(NtCreateFile_index, o_NtCreateFile);
        kaspersky::unhook_ssdt_routine(NtQuerySystemInformation_index, o_NtQuerySystemInformation);
        return STATUS_UNSUCCESSFUL;
    }

    log("NtUserSetWindowDisplayAffinity hooked.");

    if (!kaspersky::hook_shadow_ssdt_routine(NtUserGetWindowDisplayAffinity_index,
        &hooks::hk_NtUserGetWindowDisplayAffinity,
        reinterpret_cast<void**>(&o_NtUserGetWindowDisplayAffinity)))
    {
        log("Failed to hook NtUserGetWindowDisplayAffinity!");
        kaspersky::unhook_ssdt_routine(NtCreateFile_index, o_NtCreateFile);
        kaspersky::unhook_ssdt_routine(NtQuerySystemInformation_index, o_NtQuerySystemInformation);
        kaspersky::unhook_shadow_ssdt_routine(NtUserSetWindowDisplayAffinity_index, o_NtUserSetWindowDisplayAffinity);
        return STATUS_UNSUCCESSFUL;
    }

    log("NtUserGetWindowDisplayAffinity hooked.");
    log("KasperskyHook fully initialized.");

    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (!kaspersky::is_klhk_loaded())
        return;


    if (NtUserGetWindowDisplayAffinity_index)
    {
        if (!kaspersky::unhook_shadow_ssdt_routine(NtUserGetWindowDisplayAffinity_index,
            o_NtUserGetWindowDisplayAffinity))
            log("Failed to unhook NtUserGetWindowDisplayAffinity.");
        else
            log("NtUserGetWindowDisplayAffinity unhooked.");
    }

    if (NtUserSetWindowDisplayAffinity_index)
    {
        if (!kaspersky::unhook_shadow_ssdt_routine(NtUserSetWindowDisplayAffinity_index,
            o_NtUserSetWindowDisplayAffinity))
            log("Failed to unhook NtUserSetWindowDisplayAffinity.");
        else
            log("NtUserSetWindowDisplayAffinity unhooked.");
    }

    if (!kaspersky::unhook_ssdt_routine(NtQuerySystemInformation_index,
        o_NtQuerySystemInformation))
        log("Failed to unhook NtQuerySystemInformation.");
    else
        log("NtQuerySystemInformation unhooked.");

    if (!kaspersky::unhook_ssdt_routine(NtCreateFile_index, o_NtCreateFile))
        log("Failed to unhook NtCreateFile.");
    else
        log("NtCreateFile unhooked.");


    LARGE_INTEGER delay{ };
    delay.QuadPart = -10000000; // 1 second
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    log("KasperskyHook unloaded.");
}