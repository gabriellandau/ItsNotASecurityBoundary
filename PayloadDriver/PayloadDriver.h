#pragma once

#pragma warning(disable: 4201) // warning C4201: nonstandard extension used: nameless struct/union

#include <ntifs.h>
#include <ntintsafe.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <fltKernel.h>
#include <ntimage.h>
#include <bcrypt.h>
#include <wsk.h>

#define PHNT_MODE PHNT_MODE_KERNEL
#include <phnt_ntdef.h>
#include <phnt.h>
#include <ntpebteb.h>
#include <ntldr.h>

//#include <ntzwapi.h>

#define ONCE __pragma( warning(suppress:4127) ) \
             while( 0 )

#define PoolDelete(_x)\
        do{ \
            if( (_x) != NULL ) \
            { \
                ExFreePool( _x ); \
                (_x) = NULL; \
            } \
        } ONCE

#define ReferenceDelete(_x) \
        do{ \
            if( (_x) != NULL ) \
            { \
                ObDereferenceObject(_x); \
                (_x) = NULL; \
            } \
        } ONCE

#define HandleDelete(_x) \
        do{ \
            if( NULL != (_x) ) \
            { \
                ZwClose(_x); \
                (_x) = NULL; \
            } \
        } ONCE

#define CleanUpWithStatusIfFailed(_status)\
        do{ \
            NTSTATUS __status = (_status); \
            if( !(NT_SUCCESS(__status)) ) \
            { \
                ntStatus = (__status); \
                goto Cleanup; \
            } \
        } ONCE

#define CleanUpWithStatusIf(_cond, _status)\
        do{ \
            if( _cond ) \
            { \
                ntStatus = (_status); \
                goto Cleanup; \
            } \
        } ONCE

#define CleanUpWithStatus(_status)\
        do{ \
            ntStatus = (_status); \
            goto Cleanup; \
        } ONCE


// From https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;                  // Reserved
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;


// #include <ntzwapi.h>


EXTERN_C
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

EXTERN_C
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

EXTERN_C
NTSTATUS
SeLocateProcessImageName(
    _Inout_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* pImageFileName
);
