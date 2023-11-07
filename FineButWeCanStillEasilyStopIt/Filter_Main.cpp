
#include "Filter.h"

PFLT_FILTER gpFilter = NULL;

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PreAcquireForSectionSync,
      NULL },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version   
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, //  Flags
    NULL,                                   //  Context
    Callbacks,                              //  Operation callbacks
    FilterUnload,                           //  FilterUnload
    InstanceSetupCallback,                  //  InstanceSetup
    QueryTeardown,                          //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete
    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};

NTSTATUS
RegisterFilter(_In_ PDRIVER_OBJECT pDriverObject)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    ntStatus = FltRegisterFilter(pDriverObject, &FilterRegistration, &gpFilter);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ItsNotASecurityBoundary: FineButWeCanStillEasilyStopIt FltRegisterFilter() failed with status %08x", 
            ntStatus);
        goto Cleanup;
    }

    ntStatus = FltStartFiltering(gpFilter);
    if (!NT_SUCCESS(ntStatus))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ItsNotASecurityBoundary: FineButWeCanStillEasilyStopIt FltStartFiltering() failed with status %08x",
            ntStatus);
        FltUnregisterFilter(gpFilter);
        gpFilter = NULL;
        goto Cleanup;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ItsNotASecurityBoundary FineButWeCanStillEasilyStopIt RegisterFilter() success\n");

Cleanup:
    return ntStatus;
}

VOID
UnregisterFilter()
{
    if (gpFilter)
    {
        FltUnregisterFilter(gpFilter);
        gpFilter = NULL;
    }
}

NTSTATUS
FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    FltUnregisterFilter(gpFilter);

    return STATUS_SUCCESS;
}

NTSTATUS InstanceSetupCallback(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING volumeName = { 0, };
    PWCHAR pBuffer = NULL;
    ULONG volumeNameLength = 0;

    ntStatus = FltGetVolumeName(FltObjects->Volume, NULL, &volumeNameLength);
    pBuffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, volumeNameLength, POOL_TAG);
    if (!pBuffer)
    {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlInitEmptyUnicodeString(&volumeName, pBuffer, (USHORT)volumeNameLength);
    ntStatus = FltGetVolumeName(FltObjects->Volume, &volumeName, &volumeNameLength);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }
    
    // Volume Reads
    // Flags == FLTFL_INSTANCE_SETUP_AUTOMATIC_ATTACHMENT
    // VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM
    // VolumeFilesystemType == FLT_FSTYPE_NTFS

    // TODO: Raw disk reads

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
        "FineButWeCanStillEasilyStopIt: InstanceSetupCallback for Flags: 0x%x DevType: %u FS: %u for %wZ\n",
        Flags, VolumeDeviceType, VolumeFilesystemType, &volumeName);

Cleanup:
    PoolDeleteWithTag(pBuffer, POOL_TAG);

    return STATUS_SUCCESS;
}

NTSTATUS
QueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_ACCESS_DENIED;
}
