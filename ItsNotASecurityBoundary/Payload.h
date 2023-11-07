#pragma once

#include <phnt_windows.h>
#include <string>
#include <vector>

bool BuildPayload(
    const std::wstring& driverPath,
    const std::string& benignBuffer,
    std::string& payloadBuffer,
    ULONGLONG& patchedRangeStart,
    ULONGLONG& patchedRangeEnd,
    const std::string& authentihashToReplace);


// mscat.h doesn't play nicely with phnt
typedef HANDLE          HCATADMIN;
_Success_(return != FALSE)
EXTERN_C BOOL WINAPI CryptCATAdminAcquireContext2(
    _Out_       HCATADMIN * phCatAdmin,
    _In_opt_    const GUID * pgSubsystem,
    _In_opt_    PCWSTR      pwszHashAlgorithm,
    _In_opt_    PVOID pStrongHashPolicy,
    _Reserved_  DWORD       dwFlags
);

_Success_(return != FALSE)
EXTERN_C BOOL WINAPI CryptCATAdminCalcHashFromFileHandle2(
    _In_        HCATADMIN   hCatAdmin,
    _In_        HANDLE      hFile,
    _Inout_     DWORD * pcbHash,
    _Out_writes_bytes_to_opt_(*pcbHash, *pcbHash) BYTE * pbHash,
    _Reserved_  DWORD       dwFlags
);

EXTERN_C BOOL WINAPI      CryptCATAdminReleaseContext(IN HCATADMIN hCatAdmin,
    IN DWORD dwFlags);