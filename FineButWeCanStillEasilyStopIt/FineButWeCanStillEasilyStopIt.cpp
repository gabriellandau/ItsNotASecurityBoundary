
#include "Filter.h"

void DriverUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

EXTERN_C NTSTATUS DriverEntry(
    _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // TODO: Fail to load if HVCI is enabled
    // FlagOn(ZwQuerySystemInformation(SystemCodeIntegrityInformation).CodeIntegrityOptions, 
    //          CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED | CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED)

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ItsNotASecurityBoundary FineButWeCanStillEasilyStopIt DriverEntry()\n");

    {
        MEMORY_RANGE_ENTRY mre = { 0 };
        FindCiDll(&mre);
    }

    DriverObject->DriverUnload = DriverUnload;

    RegisterFilter(DriverObject);

    return STATUS_SUCCESS;
}
