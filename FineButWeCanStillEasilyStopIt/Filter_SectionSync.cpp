#include "FineButWeCanStillEasilyStopIt.h"
#include <aux_klib.h>

// Data->RequestorMode is KernelMode in many cases where you wouldn't expect it to be, such as async I/O and network redirectors.  
// SL_FORCE_ACCESS_CHECK is a better indicator of a UserMode requestor. See this writeup by James Forshaw: 
// https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html
// This function is based on the IRP_MJ_CREATE code for Ntfs!NtfsEffectiveMode from Win10 21H2 and Win11 22H2 (they match),
// decompiled here: https://gist.github.com/gabriellandau/d5cda8b3e42547bb12c86a6d2bf243b4#file-ntfseffectivemode-win11-22h2-c-L10-L19
KPROCESSOR_MODE GetCreateIrpEffectiveMode(PFLT_CALLBACK_DATA Data)
{
    if (!Data)
    {
        return ExGetPreviousMode();
    }

    NT_ASSERT(IRP_MJ_CREATE == Data->Iopb->MajorFunction);

    if (FlagOn(Data->Iopb->OperationFlags, SL_FORCE_ACCESS_CHECK))
    {
        return UserMode;
    }

    return Data->RequestorMode;
}

NTSTATUS IsLikelyASecurityCatalog(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PBOOL pbIsACatalog)
{
    // 1.3.6.1.4.1.311.10.1 - PKCS #7 ContentType Object Identifier for Certificate Trust List
    const static BYTE gCtlOid[11] = { 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x01 };

        NTSTATUS ntStatus = STATUS_SUCCESS;
    PBYTE pBuffer = NULL;
    const ULONG bufferMem = 64;
    ULONG bufferSize = 0;
    LARGE_INTEGER readOffset = { 0 };

    CleanUpWithStatusIf(
        !Data || !FltObjects || !FltObjects->Instance || !pbIsACatalog || !Data->Iopb || !Data->Iopb->TargetFileObject,
        STATUS_INVALID_PARAMETER);

    *pbIsACatalog = FALSE;

    pBuffer = (PBYTE)ExAllocatePoolWithTag(PagedPool, bufferMem, POOL_TAG);
    CleanUpWithStatusIf(!pBuffer, STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(pBuffer, bufferMem);

    CleanUpWithStatusIfFailed(FltReadFile(
        FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        &readOffset,
        bufferMem,
        pBuffer,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        &bufferSize,
        NULL,
        NULL));

    // Check header magic
    switch (*(PUSHORT)pBuffer)
    {
    case 0x8230:
    case 0x8330:
        break;
    default:
        CleanUpWithStatus(STATUS_SUCCESS);
    }

    // Search for the OID in bytes bytes 36-64
    for (SIZE_T i = 36; i + sizeof(gCtlOid) < bufferMem; i++)
    {
        if (0 == RtlEqualMemory(pBuffer + i, gCtlOid, sizeof(gCtlOid)))
        {
            *pbIsACatalog = TRUE;
            CleanUpWithStatus(STATUS_SUCCESS);
        }
    }

Cleanup:
    PoolDelete(pBuffer);

    return ntStatus;
}

NTSTATUS FindCiDll(PMEMORY_RANGE_ENTRY pModuleInfo)
{
    static MEMORY_RANGE_ENTRY sCachedResult = { 0, };
    static NTSTATUS sCachedReturnCode = STATUS_SUCCESS;
    static bool sbLookupAttempted = false;

    // >>> s = "\\SystemRoot\\system32\\CI.dll"
    // >>> [0xF3 ^ ord(s[i]) ^ i for i in range(len(s))]
    // [175, 161, 136, 131, 131, 147, 152, 166, 148, 149, 141, 164, 140, 135, 142, 136, 134, 143, 210, 210, 187, 165, 172, 202, 143, 134, 133]
    const static BYTE ciDllObfuscated[27] = { 175, 161, 136, 131, 131, 147, 152, 166, 148, 149, 141, 164, 140, 135, 142, 136, 134, 143, 210, 210, 187, 165, 172, 202, 143, 134, 133 };
    BYTE ciDllDeobfucated[27 + 1] = { 0, };
    STRING ciDll = { 0, };

    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    PAUX_MODULE_EXTENDED_INFO pModules = NULL;
    ULONG nModules = 0;

    if (sbLookupAttempted)
    {
        *pModuleInfo = sCachedResult;
        CleanUpWithStatus(sCachedReturnCode);
    }

    CleanUpWithStatusIfFailed(AuxKlibInitialize());

    (void)AuxKlibQueryModuleInformation(&bufferSize, sizeof(*pModules), NULL);
    CleanUpWithStatusIf(0 == bufferSize, STATUS_UNSUCCESSFUL);

    bufferSize *= 2;
    pModules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG);
    CleanUpWithStatusIf(!pModules, STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(pModules, bufferSize);

    CleanUpWithStatusIfFailed(AuxKlibQueryModuleInformation(&bufferSize, sizeof(*pModules), pModules));
    nModules = bufferSize / sizeof(*pModules);

    // Deobfuscate "\\SystemRoot\\system32\\CI.dll"
    for (size_t i = 0; i < sizeof(ciDllObfuscated); i++)
    {
        ciDllDeobfucated[i] = ciDllObfuscated[i] ^ 0xF3 ^ (BYTE)i;
    }
    CleanUpWithStatusIfFailed(RtlInitAnsiStringEx(&ciDll, (char*)ciDllDeobfucated));

    for (size_t i = 0; i < nModules; i++)
    {
        PAUX_MODULE_EXTENDED_INFO pModuleIter = pModules + i;
        STRING modulePath = { 0 };

        if (!NT_SUCCESS(RtlInitAnsiStringEx(&modulePath, (char*)pModuleIter->FullPathName)))
        {
            continue;
        }

        if (!RtlEqualString(&modulePath, &ciDll, TRUE))
        {
            continue;
        }

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ItsNotASecurityBoundary FindCiDll %p: %s\n", pModuleIter->BasicInfo.ImageBase, pModuleIter->FullPathName);

        pModuleInfo->VirtualAddress = pModuleIter->BasicInfo.ImageBase;
        pModuleInfo->NumberOfBytes = pModuleIter->ImageSize;

        sCachedResult = *pModuleInfo;
        sCachedReturnCode = STATUS_SUCCESS;
        sbLookupAttempted = true;
        CleanUpWithStatus(STATUS_SUCCESS);
    }

    sCachedResult = { NULL, 0 };
    sCachedReturnCode = STATUS_NOT_FOUND;
    sbLookupAttempted = true;
    CleanUpWithStatus(STATUS_NOT_FOUND);

Cleanup:
    PoolDelete(pModules);

    return ntStatus;
}

#define MAX_CALLSTACK 32
BOOL IsCalledByCodeIntegrity()
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PVOID* pCallstack = NULL;
    ULONG frameCount = 0;
    static MEMORY_RANGE_ENTRY ciDll = { NULL, };

    if (!ciDll.VirtualAddress)
    {
        CleanUpWithStatusIfFailed(FindCiDll(&ciDll));
    }

    pCallstack = (PVOID*)ExAllocatePoolWithTag(PagedPool, sizeof(*pCallstack) * MAX_CALLSTACK, POOL_TAG);
    CleanUpWithStatusIf(!pCallstack, STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(pCallstack, sizeof(*pCallstack) * MAX_CALLSTACK);

    frameCount = RtlCaptureStackBackTrace(0, MAX_CALLSTACK, pCallstack, NULL);
    CleanUpWithStatusIf(0 == frameCount, STATUS_SUCCESS);

    for (ULONG i = 0; i < frameCount; i++)
    {
        if ((pCallstack[i] >= ciDll.VirtualAddress) &&
            ((ULONG_PTR)pCallstack[i] < ((LONG_PTR)ciDll.VirtualAddress + ciDll.NumberOfBytes)))
        {
            bResult = TRUE;
            break;
        }
    }

Cleanup:
    PoolDelete(pCallstack);

    return bResult;
}

FLT_PREOP_CALLBACK_STATUS
PreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS cbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PEPROCESS pProcess = FltGetRequestorProcess(Data);;
    FILE_ATTRIBUTE_TAG_INFORMATION fileTagInfo = { 0 };
    PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
    BOOL bIsACatalog = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    // We're only interested in SyncTypeCreateSection + PAGE_READONLY + FILE_REMOTE_DEVICE
    CleanUpWithStatusIf(SyncTypeCreateSection != Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType,
        STATUS_SUCCESS);
    CleanUpWithStatusIf(PAGE_READONLY != Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
        STATUS_SUCCESS);
    CleanUpWithStatusIf(!FlagOn(Data->Iopb->TargetFileObject->DeviceObject->Characteristics, FILE_REMOTE_DEVICE),
        STATUS_SUCCESS);

    // We are looking for PreviousMode == KernelMode actions taken by the System process
    CleanUpWithStatusIf(pProcess != PsInitialSystemProcess, STATUS_SUCCESS);
    CleanUpWithStatusIf(KernelMode != GetCreateIrpEffectiveMode(Data), STATUS_SUCCESS);
    
    // The request should come from CI.DLL
    CleanUpWithStatusIf(!IsCalledByCodeIntegrity(), STATUS_SUCCESS);

    // The file should have a security catalog OID near its header
    CleanUpWithStatusIfFailed(IsLikelyASecurityCatalog(Data, FltObjects, &bIsACatalog));
    CleanUpWithStatusIf(!bIsACatalog, STATUS_SUCCESS);

    // Get requested filename
    CleanUpWithStatusIfFailed(FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_ALLOW_QUERY_ON_REPARSE, &pNameInfo));
    CleanUpWithStatusIfFailed(FltParseFileNameInformation(pNameInfo));
        
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "PreAcquireForSectionSync: BLOCKED PageProtection %08x Flags %08x Path: %wZ\n", 
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
        Data->Iopb->Parameters.AcquireForSectionSynchronization.Flags,
        &pNameInfo->Name);

    // At this point, we have a IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION for a FILE_REMOTE_DEVICE SEC_COMMIT within the System process.
    // Perform the block
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    cbStatus = FLT_PREOP_COMPLETE;

Cleanup:
    if (pNameInfo)
    {
        FltReleaseFileNameInformation(pNameInfo);
    }

    return cbStatus;
}
